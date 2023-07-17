import asyncio as _asyncio
import binascii

import datetime
import json
import logging
from aiohttp import FormData
from typing import Any, ClassVar, NewType
from dataclasses import asdict, dataclass
import uuid
from jwt import decode as jwt_decode
from jwt import PyJWKClient, PyJWKClientError, InvalidTokenError
import aiohttp
import base64
import jsonpatch
from urllib.parse import urljoin

from app.serialize import to_dict

from .images import GitlabImage
from .exceptions import (  # noqa: F401
    GitlabError,
    GitlabLookupError,
    _ClientResponseBodyError,
    EntityAlreadyExists,
    LookupErrors,
    Unauthorized,
    InvalidCredentialsError,
    InvalidFileSizeError
)
from .models import (  # noqa: F401
    UserInfo,
    RegisterData,
    Creator,
    ResourceTypeEnum,
    Resource,
    Lesson,
    LevelEnum,
    LearningTrackData,
    LearningTrackSuggestion,
    LearningTrackMetadata,
    AllLearningTracks,
    ResourceProgress,
    UserProgress,
    LearningTrackCommit
)


GRANT_TYPE = "password"  # Resource owner password credentials flow
SCOPES = frozenset(["api", "openid", "email"])  # Scopes to request
GITLAB_MAX_IMAGE_SIZE = 200000  # 200KB
API_MAX_IMAGE_SIZE = 3145728   # 3MB

GitlabAccessToken = NewType("GitlabAccessToken", str)
GitlabRefreshToken = NewType("GitlabRefreshToken", str)
GitlabAdminPass = NewType("GitlabAdminPass", str)


@dataclass
class GitlabConfig:
    """Configuration for Gitlab.

    Attributes:
        gitlab_hostname: Hostname of the Gitlab instance.
    """

    gitlab_hostname: str


@dataclass
class GitlabToken:
    """A Gitlab token.

    Attributes:
        access_token: Access token.
        token_type: Type of the token.
        expiration_date: Expiration date of the token.
        refresh_token: Refresh token.
    """

    access_token: GitlabAccessToken
    token_type: str
    expiration_date: datetime.datetime
    refresh_token: GitlabRefreshToken


class Gitlab:
    """Facade for Gitlab APISAS.

    This class is responsible for handling all the interactions with
    Gitlab API.

    Note: All requests can raise an asyncio.TimeoutError if the request
    takes too long.

    Attributes:
        config: Gitlab configuration.
        session: aiohttp.ClientSession to use for requests.
        access_token: Access token to use for requests. This token must
            have the necessary scopes to perform the requests.
        max_timeout: Maximum timeout for requests in seconds.
    """

    _rsa_cache: ClassVar[dict[str, PyJWKClient]] = {}
    """Cache for RSA public keys used for oidc verification.

    Maps the hostname to the client used to extract the key.

    The client itself has a built-in cache.
    """
    _lock: ClassVar[_asyncio.Lock] = _asyncio.Lock()
    """Lock to prevent concurrent fetching of JWT keys."""

    _JWT_ALGORITHMS = ["RS256"]
    """Algorithms supported by Gitlab for parsing JWT oidc tokens."""

    user_info: UserInfo | None = None
    access_token: GitlabAccessToken | None = None

    max_timeout: float = 10
    """Maximum timeout for requests in seconds."""

    def __init__(
        self,
        *,
        config: GitlabConfig,
        access_token: GitlabAccessToken | None = None,
        session: aiohttp.ClientSession | None = None,
    ):
        """Initialize Gitlab.

        Args:
            access_token: Access token to use for requests. This token must
                have the necessary scopes to perform the requests.
            config: Gitlab configuration.
            session: aiohttp.ClientSession to use for requests.
                If None, a new session will be created.
        """
        if access_token:
            self.access_token = access_token
        self.config = config
        self.session = session or aiohttp.ClientSession()

    def __repr__(self):
        if self.access_token:
            return "{0} {1}".format(
                f"<{self.__class__.__name__} ",
                f"access_token={self.access_token[:4]}...>"
            )
        return (
            f"<{self.__class__.__name__} "
            f"(access_token={self.access_token})>")  # Can be empty string

    def _endpoint(self, path: str):
        return urljoin(self.config.gitlab_hostname, path)

    async def _parse_jwt(self, token: str) -> dict[str, Any]:
        """Parse a JWT token.

        Args:
            token: JWT token to parse.

        Returns:
            The parsed token.

        Raises:
            GitlabError: If the token is invalid.
        """
        try:
            client = self._rsa_cache[self.config.gitlab_hostname]
        except KeyError:
            client = PyJWKClient(
                self._endpoint("/oauth/discovery/keys"),
                cache_keys=True,
                lifespan=60 * 30
            )
            self._rsa_cache[self.config.gitlab_hostname] = client

        try:
            async with self._lock:
                signing_key = await _asyncio.to_thread(
                    client.get_signing_key_from_jwt,
                    token
                )

            return jwt_decode(token,
                              key=signing_key.key,
                              algorithms=self._JWT_ALGORITHMS)
        except (PyJWKClientError, InvalidTokenError) as e:
            raise GitlabError("Invalid JWT token") from e

    async def login(self, *, username: str,
                    password: str) -> tuple[GitlabToken, UserInfo]:
        """Login to Gitlab.

        The login will be carried using Resource owner password credentials
        flow of OAuth2.

        Args:
            username: Username of the user.
            password: Password of the user.

        Returns:
            A GitlabToken and UserInfo.

        Raises:
            aiohttp.ClientResponseError: If the request fails.
            GitlabError: If the response is invalid.
            asyncio.TimeoutError: If the request takes too long / gitlab
                is down.
        """

        try:
            result = await self._request_json(
                "POST",
                "/oauth/token",
                base_path="",
                data={
                    "grant_type": GRANT_TYPE,
                    "username": username,
                    "password": password,
                    "scope": " ".join(SCOPES),
                },
            )
        except aiohttp.ClientResponseError as e:
            if e.status == 400:
                # Maybe should be ValueError...?
                raise InvalidCredentialsError("Invalid credentials") from e
            raise  # pragma: no cover

        try:
            id_json = await self._parse_jwt(result["id_token"])

            info = UserInfo(
                id=id_json["sub"],
                name=id_json["name"],
                username=id_json["preferred_username"],
                email=id_json["email"],
            )

            self.user_info = info
            token = self.access_token = GitlabAccessToken(
                result["access_token"])

            return (
                GitlabToken(
                    access_token=token,
                    token_type=result["token_type"],
                    expiration_date=(
                        datetime.datetime.now(datetime.UTC)
                        + datetime.timedelta(seconds=result["expires_in"])
                    ),
                    refresh_token=result["refresh_token"],
                ),
                self.user_info,
            )
        except KeyError as e:
            raise GitlabError("Invalid data returned by Gitlab") from e

    async def register(self, user_data: RegisterData):
        """Register a user.
        Admin access is required to perform this request.

        Args:
            user_data: Data to register a user.

        Raises:
            GitlabError: If the response is invalid.
            EntityAlreadyExists: If the username or email is already taken.
            ValueError: If the data is invalid.
            aiohttp.ClientResponseError: If the request fails.
        """

        data_dictionary = asdict(user_data)

        try:
            await self._request_json(
                "POST",
                "/users",
                base_path="/api/v4/",
                data=data_dictionary,
            )

        except _ClientResponseBodyError as e:
            if e.status == 409:
                message = e.body["message"]

                if "Username has already been taken" in message:
                    raise EntityAlreadyExists(
                        "username",
                        entity=user_data.username) from e

                if "Email has already been taken" in message:
                    raise EntityAlreadyExists(
                        "email", entity=user_data.email) from e
            elif e.status == 400:
                message = e.body["message"]
                if err := message.get("password"):
                    raise ValueError(f"Invalid password: {err[0]}")
                raise ValueError(f"Invalid data received: {message}") from e
            raise

    async def refresh_token(self, token: GitlabRefreshToken) -> GitlabToken:
        """Refresh a Github token.

        Args:
            token: Refresh token to use.

        Returns:
            A new GitlabToken.

        Raises:
            GitlabError: If the response is invalid.
            aiohttp.ClientResponseError: If the request fails.
        """

        result = await self._request_json(
            "POST",
            "/oauth/token",
            base_path="",
            data={
                "grant_type": "refresh_token",
                "refresh_token": token,
            },
        )

        try:
            return GitlabToken(
                access_token=GitlabAccessToken(result["access_token"]),
                token_type=result["token_type"],
                expiration_date=(
                    datetime.datetime.now(datetime.UTC)
                    + datetime.timedelta(seconds=result["expires_in"])
                ),
                refresh_token=GitlabRefreshToken(result["refresh_token"]),
            )
        except KeyError as e:
            raise GitlabError("Invalid response from Gitlab") from e

    async def _request_json(
        self,
        method: str,
        path: str, *args,
        base_path: str = "/api/v4/",
        **kwargs
    ) -> dict[str, Any]:
        """Make a request to Gitlab API and return the JSON response.

        Args:
            method: HTTP method to use.
            path: Path to request.
            *args: Positional arguments to pass to the request.
            **kwargs: Keyword arguments to pass to the request.

        Returns:
            JSON response.

        Raises:
            aiohttp.ClientResponseError: If the request fails.
        """

        path = path.lstrip("/")
        headers = kwargs.setdefault("headers", {})

        if self.access_token is not None and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.access_token}"

        timeout = aiohttp.ClientTimeout(
            total=kwargs.pop("timeout", self.max_timeout))

        async with self.session.request(
            method, self._endpoint(urljoin(base_path, path)), *args,
            timeout=timeout,
            **kwargs
        ) as response:

            # This assumes all responses are JSON, which is *hopefully*
            # true for Gitlab. Otherwise an exception will be thrown.
            if ((response.content_length is not None and
                    response.content_length > 0) or
                    # TODO: Make sure Gitlab always returns JSONs.
                    # Gitlab's API sometimes does not have the
                    # content-length header :shrug:
                    response.status in (200, 201)):
                # In order to get the body of the error we need to keep the
                # response before the exception is thrown
                if response.content_type == "text/plain":
                    body = await response.text()
                elif response.content_type in ["image/png"]:
                    body = await response.read()
                else:
                    body = await response.json()
            else:
                body = {}

            try:
                response.raise_for_status()
            except aiohttp.ClientResponseError as e:
                e = _ClientResponseBodyError.from_error(e, body)
                if 500 <= response.status < 600:
                    raise GitlabError(
                        f"Gitlab returned status code {response.status}"
                    ) from e
                if response.status == 401:
                    raise Unauthorized() from e
                raise e
            return body

    async def get_user_info(self) -> UserInfo:
        """Get user info.

        Returns:
            User info.

        Raises:
            GitlabError: If the response is invalid.
            aiohttp.ClientResponseError: If the request fails.
        """

        result = await self._request_json("GET", "/user")

        try:
            return UserInfo(
                id=result["sub"],
                name=result["name"],
                username=result["preferred_username"],
                email=result["email"],
            )
        except KeyError as e:
            raise GitlabError("Invalid response from Gitlab") from e

    async def get_learning_track(self, learning_track_id: int,
                                 change_id: str = None) -> LearningTrackData:
        """Get a specific Learning Track based on the ID recieved
        Args:
            learning_track_id: String with the larning track ID to get..
            change_id: Commit id

        Returns:
            The learning track with the ID requested.

        Raises:
            GitlabLookupError: If the resource track does not exist.
                - commit
                - learning_track
            KeyError: If the GitLab return invalid data.
        """

        try:
            result = await self._request_json(
                "GET",
                f"projects/{learning_track_id}/repository/files/track.json",
                params={"ref": change_id if change_id else "main"}
            )
        except _ClientResponseBodyError as e:
            if e.status == 404:
                error_message = e.body.get("message")
                if error_message == "404 Commit Not Found":
                    raise GitlabLookupError(resource_type=LookupErrors.commit)

                raise GitlabLookupError(
                    resource_type=LookupErrors.learning_track)

            raise

        result = json.loads(
            base64.b64decode(
                result["content"]).decode("UTF-8"))

        result_metadata = await self._request_json(
            "GET",
            f"projects/{learning_track_id}"
        )

        try:
            lessons = []
            if result["lessons"]:
                for lesson_data in result["lessons"]:
                    resources = []
                    for resource_data in lesson_data["resources"]:
                        resources.append(Resource(**resource_data))
                    lesson_data["resources"] = resources
                    lesson = Lesson(**lesson_data)
                    lessons.append(lesson)

            creator = Creator(
                name=result_metadata["owner"]["name"],
                avatar=result_metadata["owner"]["avatar_url"],
                username=result_metadata["owner"]["username"],
                creator_id=result_metadata["owner"]["id"],
            )
            description_json = json.loads(result_metadata["description"])

            ext = result_metadata["avatar_url"].split('.')[-1]

            image_response = await self._request_json(
                "GET",
                result_metadata["avatar_url"],
                base_path="",
            )
            base64_data = base64.b64encode(image_response).decode('utf-8')
            dataurl = f'data:image/{ext};base64,{base64_data}'

            return LearningTrackData(
                learning_track_id=result_metadata["id"],
                is_draft=result_metadata[
                    "builds_access_level"] == "disabled",
                is_private=result_metadata["visibility"] != "public",
                # Strip uniquifying UUID suffix
                title=result_metadata["name"][:-7],
                career=description_json["career"],
                career_path=description_json["career_path"],
                description=description_json["description"],
                thumbnail_image=dataurl,
                level=description_json["level"],
                tags=result_metadata["topics"],
                skills=result["skills"],
                createdBy=creator,
                lessons=lessons
            )

        except KeyError as e:
            raise GitlabError("Invalid response from Gitlab") from e

    async def get_learning_tracks(self,
                                  search: str
                                  ):
        """Get all Learning Tracks based on the search query"""
        result = await self._request_json(
            "GET",
            "projects?search=" + search)

        hasResults = True
        if len(result) == 0:
            hasResults = False
            result = await self._request_json(
                "GET",
                "projects")

        learning_tracks = []
        creator = None
        for learning_track in result:
            if "owner" in learning_track:
                creator = Creator(
                    name=learning_track["owner"]["name"],
                    avatar=learning_track["owner"]["avatar_url"],
                    username=learning_track["owner"]["username"],
                    creator_id=learning_track["owner"]["id"]
                )

            description_json = json.loads(learning_track["description"])
            ext = learning_track["avatar_url"].split('.')[-1]

            async with aiohttp.ClientSession() as session:
                async with session.get(
                        learning_track["avatar_url"]) as response:
                    response.image = await response.read()
                    base64_data = base64.b64encode(
                        response.image).decode('utf-8')

            dataurl = f'data:image/{ext};base64,{base64_data}'
            learning_track_info = LearningTrackMetadata(
                learning_track_id=learning_track["id"],
                title=learning_track["name"][:-7],
                is_draft=learning_track[
                    "builds_access_level"] == "disabled",
                is_private=learning_track["visibility"] != "public",
                career=description_json["career"],
                description=description_json["description"],
                thumbnail_image=dataurl,
                tags=learning_track["topics"],
                createdBy=creator,
                level=description_json["level"],
                career_path=description_json["career_path"]
            )

            if learning_track_info.is_draft is False:
                learning_tracks.append(learning_track_info)

        all_learning_tracks = AllLearningTracks(
            learning_tracks=learning_tracks,
            hasResults=hasResults
        )

        return all_learning_tracks

    async def post_learning_track(
            self, learning_track: LearningTrackData) -> int:
        """Post a new learning track to GitLab.

        Returns:
            The learning track ID.

        Raises:
            GitlabError: If the response is invalid.
            aiohttp.ClientResponseError: If the request fails.
        """

        # ~50% chance of collision at 4820 same named
        # titles according to birthday paradox.
        # sufficient for our use case.
        title_uuid = uuid.uuid4().hex[:6]

        description_data = {
            "description": learning_track.description,
            "career": learning_track.career,
            "career_path": learning_track.career_path,
            "level": learning_track.level.value
        }

        try:
            decoded_image = GitlabImage.get_image(
                base64.b64decode(learning_track.thumbnail_image),
                API_MAX_IMAGE_SIZE,
                GITLAB_MAX_IMAGE_SIZE,
            )
        except binascii.Error as e:
            raise ValueError("Invalid image.") from e
        except ValueError as e:
            raise ValueError("Invalid image.") from e

        try:
            # Create the learning track repository
            result = await self._request_json(
                "POST",
                "/projects",
                json={
                    # Due to limitations in metadata fields we are saving the
                    # career as part of the description
                    "description": json.dumps(description_data),
                    "builds_access_level": "disabled" \
                    if learning_track.is_draft else "enabled",
                    "visibility": "private" \
                    if learning_track.is_private else "public",
                    # Randomize the name so we can have multiple learning
                    # tracks with the same name
                    "name": learning_track.title + " " + title_uuid,
                    "topics": learning_track.tags
                }
            )

        except aiohttp.ClientResponseError as e:
            if e.status == 400:
                raise ValueError("Invalid learning track.") from e
            raise e  # pragma: no cover

        learning_track_id = str(result["id"])

        data = FormData()
        data.add_field(
            "avatar",
            decoded_image,
            filename="avatar.jpg",
            content_type="image/jpeg"
        )

        try:
            async with _asyncio.TaskGroup() as tg:
                tg.create_task(self._request_json(
                    "PUT", "/projects/" + learning_track_id,
                    data=data
                ))

                raw_learning_track = to_dict(learning_track)
                json_raw = {k: raw_learning_track[k] for k in
                            {"skills", "lessons"}}

                tg.create_task(self._request_json(
                    "POST", "/projects/" + learning_track_id +
                    "/repository/files/track.json",
                    json={
                        "branch": "main",
                        "content": json.dumps(json_raw),
                        "commit_message": "Create learning track"
                    }
                ))

        except* aiohttp.ClientResponseError:
            # if writing the image or the track file fails we want to
            # delete the repo
            try:
                await self._request_json("DELETE",
                                         f"projects/{learning_track_id}")
            except aiohttp.ClientResponseError:
                # if it fails we want to try again
                try:
                    await self._request_json("DELETE",
                                             "projects/" + learning_track_id)
                except aiohttp.ClientResponseError:
                    raise ValueError(
                        "Invalid learning track, impossible to"
                        "rollback the transaction for learning"
                        f"track {learning_track_id}"
                    )
            raise

        return int(learning_track_id)

    async def get_snippet_id(self) -> str:
        """Get the ID of the snippet that stores the user's progress.

        Returns:
            The ID of the snippet that stores the user's progress.

        Raises:
            GitlabError: If it is not possible to get the snippet.
        """
        try:
            result = await self._request_json(
                "GET", "snippets/"
            )

            snippet_id = - 1  # Snippet doesn't exist
            for snippet in result:
                if snippet["title"] == "User Progress":
                    snippet_id = snippet["id"]
                    break

            return snippet_id

        except aiohttp.ClientResponseError:
            raise GitlabError("Error getting the user's current progress.")

    async def get_learning_tracks_progress(self,
                                           snippet_id: int = -2
                                           ) -> list[UserProgress]:
        """Get the progress of across all learning tracks for a user.

        Args:
            user_id: The user ID.
            snippet_id: The ID of the snippet that stores the user's progress.
            A value of -2 will get the ID of the snippet from gitlab.
            learning_track_id: The ID of the learning track. If no value is
            passed progress across all learning tracks will be returned.

        Returns:
            The learning track progress across all learning tracks.
        """
        if snippet_id == -2:
            snippet_id = await self.get_snippet_id()

        learning_tracks = []

        if snippet_id == -1:
            return learning_tracks

        try:
            total_progress = await self._request_json(
                "GET", "snippets/" + str(snippet_id) + "/raw"
            )

            total_progress = json.loads(total_progress)

            for learning_track in total_progress:
                current_progress = []
                for progress in learning_track["progress"]:
                    current_progress.append(ResourceProgress(**progress))
                learning_tracks.append(UserProgress(
                    progress=current_progress,
                    learning_track_id=learning_track["learning_track_id"]
                ))

            # If no learning track ID is passed return all learning tracks

            return learning_tracks

        except aiohttp.ClientResponseError:
            raise ValueError("Error getting the user's current progress.")

    async def get_learning_track_progress(self,
                                          learning_track_id: int,
                                          snippet_id: int = -2
                                          ) -> list[ResourceProgress]:
        """Get the progress of a learning track for a user.

        Args:
            user_id: The user ID.
            learning_track_id: The learning track ID.

        Returns:
            The learning track progress.
        """

        # If the learning track doesn't exist no point fetching the progress
        try:
            await self._request_json(
                "GET",
                "projects/"
                + str(learning_track_id))
        except _ClientResponseBodyError as e:
            if e.status == 404:
                raise LookupError("Learning track not found.")
            raise

        all_progress = await self.get_learning_tracks_progress(
            snippet_id=snippet_id)

        progress = []
        found = False
        for learning_track in all_progress:
            if learning_track.learning_track_id == learning_track_id:
                progress = learning_track.progress
                found = True
                break

        if not found:
            raise LookupError("User progress not found.")

        return progress

    async def put_learning_track_progress(
            self, learning_track_id: int,
            learning_track_progress: UserProgress
    ):
        """Update the progress of a learning track for a user.

        Args:
            user_id: The user ID.
            learning_track_id: The learning track ID.
            learning_track_progress: The learning track progress.

        Raises:
            LookupError: If the user does not exist.
            GitlabError: If the response is invalid.
            aiohttp.ClientResponseError: If the request fails.
        """

        try:
            # If the learning track doesn't exist we don't need to do anything
            await self._request_json(
                "GET",
                "projects/"
                + str(learning_track_id))
        except _ClientResponseBodyError as e:
            if e.status == 404:
                raise LookupError("Learning track not found.")
            raise

        # To minimize the number of calls to gitlab
        snippet_id = await self.get_snippet_id()

        # Get a list of the current user’s tracks in progress.
        current_progress = await self.get_learning_tracks_progress(
            snippet_id=snippet_id)

        learning_track_progress.learning_track_id = learning_track_id
        raw_progress = to_dict(learning_track_progress)

        try:
            # If the user has no progress we need to create the file
            if current_progress == []:
                # Create a new snippet.
                await self._request_json(
                    "POST", "/snippets",
                    json={
                        "title": "User Progress",
                        "file_name": "progress.json",
                        "content": json.dumps([raw_progress]),
                        "visibility": "private"
                        }
                )
            else:
                progress_exists = False
                for progress in current_progress:
                    # If progress for the learning track already exists we
                    # update it
                    if progress.learning_track_id == learning_track_id:
                        progress_exists = True
                        progress.progress = raw_progress["progress"]
                        break
                if progress_exists is False:
                    # If the progress doesn't exist we add it
                    new_user_progress = UserProgress(
                        learning_track_id=learning_track_id,
                        progress=raw_progress["progress"])

                    current_progress.append(new_user_progress)

                current_progress = [to_dict(item) for item
                                    in current_progress]

                # Update the snippet.
                await self._request_json(
                    "PUT", "/snippets/" + str(snippet_id),
                    json={
                        "title": "User Progress",
                        "file_name": "progress.json",
                        "content": json.dumps(current_progress),
                        "visibility": "private"
                        }
                )

        except aiohttp.ClientResponseError:
            raise ValueError("Error updating the user's current progress.")

    async def get_learning_track_commits(
        self,
        learning_track_id: int
    ) -> list[LearningTrackCommit]:
        try:
            result = await self._request_json(
                "GET",
                f"/projects/{learning_track_id}/repository/"
                "commits?path=track.json"
            )

        except _ClientResponseBodyError as e:
            if e.status == 404:
                raise GitlabLookupError(
                    resource_type=LookupErrors.learning_track)
            raise

        return [
            LearningTrackCommit(
                change_id=c["id"],
                change_date=c["created_at"],
                change_message=c["message"]
            ) for c in result
        ]

    async def copy_learning_track(self, learning_track_id: int) -> int:

        try:
            # If the learning track doesn't exist we don't need to do anything
            learning_track = await self._request_json(
                "GET",
                "projects/"
                + str(learning_track_id))
        except _ClientResponseBodyError as e:
            if e.status == 404:
                raise LookupError(learning_track_id)
            raise  # pragma: no cover

        title = learning_track["name"][:-6] + uuid.uuid4().hex[:6]

        try:
            result = await self._request_json(
                "POST", "/projects/" + str(learning_track_id) + "/fork",
                json={
                        "name": title,
                        # path is the hyphen separated version of the name
                        "path": title.replace(" ", "-"),
                }
            )

            id_ = result["id"]

        except aiohttp.ClientResponseError as exc:
            raise GitlabError("Error copying the learning track.") from exc

        # Suggestions are track specific so we need to delete them
        # Due to async nature of gitlab we need to wait for the file to exist
        # If the file doesn't exist the 1st try we want to try again after 1s
        # If it still doesn't exist we can ignore it
        # Using Exception because we don't know what the error will be exactly

        try:
            await self._request_json(
                "DELETE", "/projects/" + str(id_) +
                "/repository/files/suggestions.json",
                json={
                    "branch": "main",
                    "commit_message": "Remove suggestions after copying."
                }
            )
            return id_
        except (_ClientResponseBodyError, GitlabError):
            await _asyncio.sleep(1)
            try:
                await self._request_json(
                    "DELETE", "/projects/" + str(id_) +
                    "/repository/files/suggestions.json",
                    json={
                        "branch": "main",
                        "commit_message":
                        "Remove suggestions after copying."
                    }
                )
                return id_
            except (_ClientResponseBodyError, GitlabError):
                logging.warning("Delete suggestions file error.")
                return id_

    async def revert_learning_track(
            self, learning_track_id: int, change_id: str):
        """Revert a learning track to a previous commit.

        Args:
            learning_track_id: The learning track ID.
            change_id: The commit SHA to revert to.

        Raises:
            LookupError: If the learning track or commit does not exist.
            aiohttp.ClientResponseError: If the request fails.
        """
        try:
            # Revert the learning track.
            # Get the raw file from the commit
            try:
                raw_file = await self._request_json(
                    "GET", "/projects/" + str(learning_track_id) +
                    "/repository/files/track.json/raw?ref=" + change_id)
            except _ClientResponseBodyError as e:
                if e.status == 404:
                    if e.body["message"] == "404 Commit Not Found":
                        raise LookupError("change_id " + change_id)
                    elif e.body["message"] == "404 File Not Found":
                        raise LookupError("track.json")
                    else:
                        raise LookupError(learning_track_id)
                raise

            # Do a commit with the raw file
            await self._request_json(
                "PUT", "/projects/" + str(learning_track_id) +
                "/repository/files/track.json",
                json={
                    "branch": "main",
                    "commit_message": "Revert to commit " + change_id,
                    "content": raw_file
                }
            )

        except aiohttp.ClientResponseError as exc:
            raise GitlabError("Error reverting the learning track.") from exc

    async def get_root_long_term_token(self, user_id: str
                                       ) -> GitlabAccessToken:
        """Get a long term token for the root user.

        Args:
            user_id: The user ID.

        Returns:
            A long term token for the root user.

        Raises:
            GitlabError: If the response is invalid.
            aiohttp.ClientResponseError: If the request fails.
        """

        scopes = ["api", "read_user", "sudo", "read_api", "read_repository",
                  "write_repository", "admin_mode"]

        result = await self._request_json(
            "POST", "/users/" + user_id + "/personal_access_tokens",
            json={
                "name": "root",
                "scopes": scopes,
            },
        )

        try:
            return GitlabAccessToken(result["token"])
        except aiohttp.ClientResponseError:
            raise GitlabError("Error creating the personal access token.")

    async def post_suggestions(self, learning_track_id: int,
                               suggestions: list[LearningTrackSuggestion]):

        """Post suggestions to a learning track.

        Args:
            learning_track_id: The learning track ID.
            suggestions: The suggestions to post.

        Raises:
            GitlabError: If the request fails.
        """

        current_suggestions, file_exists = await self._get_suggestions(
            learning_track_id)

        for suggestion in suggestions:

            raw_suggestion = to_dict(suggestion)
            raw_suggestion.update(
                suggestion_id=str(uuid.uuid4()),
                suggestion_status="open")

            current_suggestions.append(raw_suggestion)

        try:
            # Gitlab only accepts a PUT if the file already exists
            method = "PUT" if file_exists else "POST"

            await self._request_json(
                method, "/projects/" + str(learning_track_id) +
                "/repository/files/suggestions.json",
                json={
                    "branch": "main",
                    "content": json.dumps(current_suggestions),
                    "commit_message": "Add suggestions."
                }
            )

        except aiohttp.ClientResponseError as exc:
            raise GitlabError("Error saving the suggestion.") from exc

    async def _get_suggestions(self, learning_track_id: int
                               ) -> tuple[list[LearningTrackSuggestion], bool]:

        """Get the suggestions for a learning track.

        Args:
            learning_track_id: The learning track ID.

        Returns:
            A list of suggestions and a boolean indicating if the file exists.

        Raises:
            LookupError: If the learning track does not exist.
            aiohttp.ClientResponseError: If the request fails.
        """

        try:
            result = await self._request_json(
                "GET",
                "projects/"
                + str(learning_track_id)
                + "/repository/files/suggestions.json/?ref=main")

        except _ClientResponseBodyError as e:
            if e.status != 404:
                raise
            message = e.body.get("message")
            match message:
                case "404 Project Not Found":
                    raise LookupError(str(learning_track_id))
                case "404 File Not Found":
                    # If the suggestions file doesn't exist it means there are
                    # no suggestions
                    return ([], False)
                case _:
                    raise  # pragma: no cover

        suggestions = json.loads(base64.b64decode(
            result["content"]).decode("UTF-8"))

        return (suggestions, True)

    async def get_suggestions(self, learning_track_id: int
                              ) -> list[LearningTrackSuggestion]:

        """Get the suggestions for a learning track.

        Args:
            learning_track_id: The learning track ID.

        Returns:
            A list of suggestions.
        """

        suggestions, _ = await self._get_suggestions(learning_track_id)

        return suggestions

    async def get_open_suggestions(self, learning_track_id: int
                                   ) -> list[LearningTrackSuggestion]:

        """Get the open suggestions for a learning track.

        Args:
            learning_track_id: The learning track ID.

        Returns:
            A list of open suggestions for the learning track.
        """

        suggestions = await self.get_suggestions(learning_track_id)

        suggestions = [item for item in suggestions if
                       item["suggestion_status"] == "open"]

        return suggestions

    async def edit_learning_track(self,
                                  learning_track_id: int,
                                  patch: list) -> None:
        """
        Edit a learning track.

        Args:
            patch: The patch to apply to the learning track.

        Raises:
            GitlabError: If the response is invalid.
            aiohttp.ClientResponseError: If the request fails.
        """
        try:
            # If the learning track doesn't exist we don't need to do anything
            learning_track = await self.get_learning_track(learning_track_id)
        except _ClientResponseBodyError as e:
            if e.status == 404:
                raise LookupError(learning_track_id)
            raise

        title_uuid = uuid.uuid4().hex[:6]

        try:
            edited_learning_track = LearningTrackData(**jsonpatch.apply_patch(
                to_dict(learning_track),
                patch))
        except jsonpatch.JsonPatchConflict:
            raise ValueError("Invalid patch.")

        description_data = {
            "description": edited_learning_track.description,
            "career": edited_learning_track.career,
            "career_path": edited_learning_track.career_path,
            "level": edited_learning_track.level
        }

        await self._request_json(
            "PUT", "/projects/" + str(learning_track_id),
            json={
                # Due to limitations in metadata fields we are saving the
                # career as part of the description
                "description": json.dumps(description_data),
                "builds_access_level":
                "disabled" if edited_learning_track.is_draft else "enabled",
                "visibility":
                "private" if edited_learning_track.is_private else "public",
                # Randomize the name so we can have multiple learning
                # tracks with the same name
                "name": edited_learning_track.title + " " + title_uuid,
                "topics": edited_learning_track.tags
            }
        )

        raw_learning_track = to_dict(edited_learning_track)
        json_raw = {k: raw_learning_track[k] for k in
                    {"skills", "lessons"}}

        commit_message = ""
        for operation in patch:
            new_path = operation["path"]
            commit_message = commit_message + operation["op"] +\
                " value " + new_path[1:] + "\n"

        if len(commit_message) > 72:
            commit_message = commit_message[:69] + "..."

        await self._request_json(
            "PUT", "/projects/"+str(learning_track_id) +
            "/repository/files/track.json",
            json={
                "branch": "main",
                "content": json.dumps(json_raw),
                "commit_message": commit_message
            }
        )

    async def manage_suggestion(self, learning_track_id: int,
                                suggestion_id: str, action):

        """Manage a suggestion.

        Args:
            learning_track_id: The learning track ID.
            suggestion_id: The suggestion ID.
            action: The action to perform.

        Raises:
            LookupError: If the learning track does not exist.
            LookupError: If the suggestion does not exist.
            LookupError: If the suggestion is not open.
            GitlabError: If the request fails.

        """

        suggestions = await self.get_suggestions(
            learning_track_id)

        suggestion_exists = False
        for suggestion in suggestions:
            if suggestion["suggestion_id"] == suggestion_id:
                if suggestion["suggestion_status"] != "open":
                    raise LookupError("Suggestion already managed.")
                else:
                    suggestion_exists = True
                    break

        if not suggestion_exists:
            raise LookupError("Suggestion not found.")

        commit_actions = []
        lesson_exists = False

        if action == 'approve':

            learning_track = await self._request_json(
                "GET", "projects/" + str(learning_track_id) +
                "/repository/files/track.json?ref=main")

            learning_track = json.loads(
                base64.b64decode(learning_track["content"]).decode("UTF-8"))

            for lesson in learning_track["lessons"]:
                if lesson["lesson_id"] == suggestion["lesson_id"]:
                    lesson_exists = True
                    lesson["resources"].append(suggestion["resource"])
                    break

            if lesson_exists:
                # If the lesson exists we need to update the track.json file
                commit_actions.append({
                    "action": "update",
                    "file_path": "track.json",
                    "content": json.dumps(learning_track),
                })

        # If the lesson doesn't exist we mark the suggestion as rejected
        if not lesson_exists:
            suggestion["suggestion_status"] = 'reject'
        else:
            suggestion["suggestion_status"] = action

        # The changes to the suggestions.json file we commit regardless
        commit_actions.append({
            "action": "update",
            "file_path": "suggestions.json",
            "content": json.dumps(suggestions),
        })

        try:
            await self._request_json(
                "POST", "projects/" + str(learning_track_id) +
                "/repository/commits",
                json={
                    "branch": "main",
                    "commit_message": "Add resource "
                    f"{suggestion['resource']['title']} to lesson "
                    f"{suggestion['name']}",
                    "actions": commit_actions,
                }
            )

        except aiohttp.ClientResponseError:
            raise GitlabError("Error updating the suggestion status.")

    async def delete_learning_track(self, learning_track_id: int) -> None:
        """
        Delete a learning track.

        Args:
            learning_track_id: The learning track ID.

        Raises:
            LookupError: If the learning track does not exist.
            GitlabError: If the request fails.
        """

        try:
            await self._request_json(
                "DELETE", "/projects/" + str(learning_track_id))
        except _ClientResponseBodyError as e:
            if e.status == 404:
                raise LookupError(learning_track_id)
            raise  # pragma: no cover

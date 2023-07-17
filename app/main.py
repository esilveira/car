import asyncio
from contextlib import asynccontextmanager
import datetime
import functools
from typing import Annotated, Callable, TypeVar, ParamSpec
import aiohttp
import threading
import logging

from fastapi import (
    APIRouter,
    Body,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    status
)
from pydantic import BaseModel, BaseSettings, Field, EmailStr, validator
from fastapi.middleware.cors import CORSMiddleware

from app import gitlab_facade
from app.tokens import (
    CareerCenterRefreshToken,
    CareerCenterToken,
    decode_token,
    encode_token,
)

logger = logging.getLogger("backend.main")


class AppSettings(BaseSettings):
    jwt_secret: str = Field(..., env="JWT_SECRET")
    gitlab_admin_token = ""
    gitlab_admin_pass: gitlab_facade.GitlabAccessToken = Field(
        ..., env="GITLAB_ADMIN_PASSWORD")
    register_enabled: bool = Field(True, env="REGISTER_ENABLED")

    # Note: There's also UVICORN_LOG_LEVEL.
    loglevel: int | str = Field("INFO", env="APP_LOG_LEVEL")

    @validator("loglevel")
    def validate_loglevel(cls, v):
        if isinstance(v, str):
            return logging.getLevelNamesMapping()[v.upper()]
        return v

    class Config:
        env_file = ".env"


class _GitlabSettings(BaseSettings):
    gitlab_hostname: str = Field(..., env="GITLAB_HOSTNAME")

    class Config:
        env_file = ".env"


_P = ParamSpec("_P")
_T = TypeVar("_T")


def cached(func: Callable[_P, _T]) -> Callable[_P, _T]:
    """Decorator caching the result of a function.

    The cache only holds the result of the first call to the function. The
    result is stored in the function's _cache attribute. Subsequent calls to
    the function return the cached result.

    Args:
        func: Function to cache.

    Returns:
        A wrapper around the function.
    """

    @functools.wraps(func)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        try:
            return wrapper._cache  # type: ignore
        except AttributeError:
            pass
        wrapper._cache = func(*args, **kwargs)  # type: ignore
        return wrapper._cache  # type: ignore

    def reset() -> None:
        """Reset the cache of the function."""
        try:
            del wrapper._cache  # type: ignore
        except AttributeError:
            pass

    wrapper.reset = reset  # type: ignore

    return wrapper


@cached
def get_app_settings() -> AppSettings:
    return AppSettings()  # type: ignore


@cached
def get_gitlab_config() -> gitlab_facade.GitlabConfig:
    settings = _GitlabSettings()  # type: ignore[call-arg]
    return gitlab_facade.GitlabConfig(gitlab_hostname=settings.gitlab_hostname)


def get_app_local_state(request: Request) -> threading.local:
    try:
        return request.app.state.thread_local
    except AttributeError:
        state = request.app.state.thread_local = threading.local()
        return state


# Async, otherwise FastAPI will run it in a thread pool, and will bring a
# session of a different thread.


async def get_aiohttp_session(
    state: Annotated[threading.local, Depends(get_app_local_state)]
) -> aiohttp.ClientSession:
    try:
        return state.aiohttp_session
    except AttributeError:
        session = state.aiohttp_session = aiohttp.ClientSession()
        return session


async def get_gitlab(
    session: Annotated[aiohttp.ClientSession, Depends(get_aiohttp_session)],
    config: Annotated[gitlab_facade.GitlabConfig, Depends(get_gitlab_config)],
) -> gitlab_facade.Gitlab:
    return gitlab_facade.Gitlab(session=session, config=config)


async def get_admin_gitlab(
    session: Annotated[aiohttp.ClientSession, Depends(get_aiohttp_session)],
    config: Annotated[gitlab_facade.GitlabConfig, Depends(get_gitlab_config)],
    app_settings: Annotated[AppSettings, Depends(get_app_settings)],
) -> gitlab_facade.Gitlab:

    if app_settings.gitlab_admin_token == "":

        non_admin_gitlab = gitlab_facade.Gitlab(session=session, config=config)
        try:
            result = await non_admin_gitlab.login(
                username='root', password=app_settings.gitlab_admin_pass)

            admin_gitlab = gitlab_facade.Gitlab(
                session=session, config=config,
                access_token=result[0].access_token
            )

            app_settings.gitlab_admin_token = \
                await admin_gitlab.get_root_long_term_token(result[1].id)

        except gitlab_facade.GitlabError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid admin password.")
        except asyncio.TimeoutError:
            raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                                detail="Gitlab server timed out.")

    return gitlab_facade.Gitlab(
        session=session, config=config,
        access_token=app_settings.gitlab_admin_token
    )


async def get_token(
    request: Request,
    app_settings: Annotated[AppSettings, Depends(get_app_settings)]
) -> CareerCenterToken:
    """Function to get the token from the request.

    Args:
        request: The request.
        app_settings: The app settings.

    Returns:
        The token.
    """
    try:
        raw_token = request.headers.get("Authorization")
        if raw_token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header.")
        raw_token = raw_token.removeprefix("Bearer ")
        token = decode_token(
            raw_token,
            app_settings.jwt_secret,
            token_cls=CareerCenterToken)
        return token
    except ValueError as e:
        if e.args[0] == "Token expired.":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired.") from e


async def get_authenticated_gitlab(
    gitlab: Annotated[gitlab_facade.Gitlab, Depends(get_gitlab)],
    token: Annotated[CareerCenterToken, Depends(get_token)],
) -> gitlab_facade.Gitlab:
    """Function to get an authenticated gitlab instance.

    Args:
        gitlab: The gitlab instance.
        token: The token.

    Returns:
        The authenticated gitlab instance.
    """

    gitlab.access_token = token.gitlab_access_token
    return gitlab


def create_app():
    app = FastAPI(lifespan=lifespan_context)
    app.include_router(router)
    # Handle CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://localhost:9000", "https://www.mse2022uc.pt"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return app


def setup_logging():
    settings = get_app_settings()
    logging.getLogger().setLevel(settings.loglevel)


@asynccontextmanager
async def lifespan_context(app: FastAPI):
    setup_logging()
    try:
        yield
    finally:
        try:
            # Does not close from all threads, but that's fine.
            await app.state.thread_local.aiohttp_session.close()
        except AttributeError:
            pass


router = APIRouter()


class Credentials(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int
    user_info: gitlab_facade.UserInfo

    class Config:
        orm_mode = True


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: EmailStr
    full_name: str


class CreateLearningTrackResponse(BaseModel):
    learning_track_id: int


class LearningTrackHistoryDiffResponse(BaseModel):
    file: str


class GetProgressResponse(BaseModel):
    progress: list[gitlab_facade.ResourceProgress]


class AllLearningTracksProgress(BaseModel):
    progress: list[gitlab_facade.UserProgress]


@router.get("/-/health", status_code=200)
async def healthcheck():
    """Healthcheck endpoint."""
    return status.HTTP_200_OK


@router.post("/auth/register", status_code=201)
async def register(
    request: RegisterRequest,
    gitlab_api: Annotated[gitlab_facade.Gitlab, Depends(get_admin_gitlab)]
):
    """Register a new user.

    Body Args:
        username: Username of the user.
        password: Password of the user.
        email: Email of the user.
        full_name: Full name of the user.

    Returns:
        201 if the user was created successfully.
    """

    if get_app_settings().register_enabled:
        _logger = logging.LoggerAdapter(logger, {"username": request.username,
                                                 "path": "/auth/register"})
        data = gitlab_facade.RegisterData(
            username=request.username,
            password=request.password,
            email=request.email,
            name=request.full_name)

        try:
            await gitlab_api.register(data)
        except gitlab_facade.EntityAlreadyExists as e:
            _logger.debug(f"Entitiy already exists {e}: {e.entity}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username/Email already exists.") from e
        except ValueError as e:
            _logger.debug(f"Invalid data {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid data - {e}") from e
        except asyncio.TimeoutError as e:
            _logger.warning("Timeout while registering user %s.",
                            request.username)
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Timeout while registering user.") from e

        logger.debug("User %s created successfuly.", data.username)

        return status.HTTP_201_CREATED
    else:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Register is not implemented.")


@router.post("/auth/login")
async def login(
    credentials: Credentials,
    gitlab_api: Annotated[gitlab_facade.Gitlab, Depends(get_gitlab)],
    app_settings: Annotated[AppSettings, Depends(get_app_settings)],
) -> LoginResponse:
    """Login to Career Center.

    Args:
        username: Username of the user.
        password: Password of the user.

    Returns:
        A token for Career Center.
    """
    _logger = logging.LoggerAdapter(
        logger, {"username": credentials.username, "path": "/auth/login"}
    )
    try:
        gitlab_token, user = await gitlab_api.login(
            username=credentials.username, password=credentials.password
        )
    except gitlab_facade.InvalidCredentialsError as e:
        _logger.debug("Invalid credentials for user %s.", credentials.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.") from e
    except asyncio.TimeoutError as e:
        _logger.warning(
            "Timeout while logging in user %s.",
            credentials.username)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Timeout while logging in.") from e
    except gitlab_facade.GitlabError as e:
        _logger.exception(
            "Error while logging in user %s.",
            credentials.username)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Error while logging in.") from e

    _logger.debug("User %s logged in.", user.username)

    gitlab_api.access_token = gitlab_token.access_token

    expiration_date = gitlab_token.expiration_date - \
        datetime.timedelta(minutes=5)

    token = encode_token(
        CareerCenterToken(
            gitlab_access_token=gitlab_token.access_token,
            exp=int(expiration_date.timestamp()),
            sub=int(user.id),
        ),
        secret=app_settings.jwt_secret,
    )

    refresh_token = encode_token(
        CareerCenterRefreshToken(
            gitlab_refresh_token=gitlab_token.refresh_token,
            exp=int(
                (expiration_date +
                 datetime.timedelta(
                     days=1)).timestamp()),
        ),
        secret=app_settings.jwt_secret,
    )

    return LoginResponse(
        access_token=token,
        refresh_token=refresh_token,
        expires_in=int(
            (expiration_date -
             datetime.datetime.now(
                 datetime.UTC)).total_seconds()),
        user_info=user,
    )


class RefreshResponse(BaseModel):
    access_token: str
    expires_in: int
    refresh_token: str


@router.post("/auth/refresh")
async def refresh(
    refresh_token: Annotated[str, Body()],
    gitlab: Annotated[gitlab_facade.Gitlab, Depends(get_gitlab)],
    app_settings: Annotated[AppSettings, Depends(get_app_settings)],
) -> RefreshResponse:
    """Refresh a Career Center token.

    Args:
        refresh_token: Refresh token.

    Returns:
        A new token for Career Center.
    """
    decoded_token = decode_token(
        refresh_token,
        app_settings.jwt_secret,
        token_cls=CareerCenterRefreshToken)

    gitlab_token = await gitlab.refresh_token(
        decoded_token.gitlab_refresh_token)

    expiration_date = gitlab_token.expiration_date - \
        datetime.timedelta(minutes=5)

    userinfo = await gitlab.get_user_info()

    token = encode_token(
        CareerCenterToken(
            gitlab_access_token=gitlab_token.access_token,
            exp=int(expiration_date.timestamp()),
            sub=int(userinfo.id),
        ),
        secret=get_app_settings().jwt_secret,
    )

    refresh_token = encode_token(
        CareerCenterRefreshToken(
            gitlab_refresh_token=gitlab_token.refresh_token,
            exp=int(
                (expiration_date + datetime.timedelta(days=1)).timestamp()
            ),
        ),
        secret=get_app_settings().jwt_secret,
    )

    return RefreshResponse(
        access_token=token,
        refresh_token=refresh_token,
        expires_in=int(
            (expiration_date -
             datetime.datetime.now(
                 datetime.UTC)).total_seconds()),
    )


@router.get("/learning-tracks/{learning_track_id}", status_code=200)
async def get_learning_track(
    learning_track_id: int,
    gitlab_api: Annotated[
        gitlab_facade.Gitlab,
        Depends(get_authenticated_gitlab)
    ]
) -> gitlab_facade.LearningTrackData:
    """Retrieve a specific learning track by id.

    Parameter Args:
        learning_track_id: The learning track id.

    Returns:
        200 if the learning track was retrieved successfully.
        404 if learning track not found.
    """
    _logger = logging.LoggerAdapter(logger,
                                    {"path": "/learning-tracks/"
                                     "learning_track_id"})
    _logger.debug("Getting learning track id %s", learning_track_id)
    try:
        return await gitlab_api.get_learning_track(learning_track_id)
    except gitlab_facade.GitlabLookupError as e:
        _logger.debug("Learning track not found")
        raise HTTPException(status_code=404,
                            detail="Learning track not found.") from e


@router.get("/learning-tracks", status_code=200)
async def get_all_learning_tracks(
    search: str,
    gitlab_api: Annotated[gitlab_facade.Gitlab,
                          Depends(get_authenticated_gitlab)]
) -> gitlab_facade.AllLearningTracks:
    """Retrieve a list of learning tracks based on a search parameter.

    Parameter Args:
        search: The search parameter.

    Returns:
        200 if the learning tracks were retrieved successfully.
    """

    _logger = logging.LoggerAdapter(logger,
                                    {"path": "/learning-tracks"})

    _logger.debug("Searching for %s", search)

    try:
        return await gitlab_api.get_learning_tracks(search)
    except LookupError as e:
        raise HTTPException(
            status_code=404,
            detail=f"Learning track {e.args[0]} not found.") from e
    except asyncio.TimeoutError as e:
        _logger.warning("Timeout while searching for learning tracks:  %s.",
                        search)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Timeout while creating learning track.") from e


@router.post("/learning-tracks", status_code=201)
async def post_learning_track(
    request: gitlab_facade.LearningTrackData,
    gitlab_api: Annotated[
        gitlab_facade.Gitlab,
        Depends(get_authenticated_gitlab)
    ],
) -> CreateLearningTrackResponse:
    """Create a learning track

    Paramether Arg:
        learning_track: The learning track to be created.

    Returns:
        200 if the learning track was created.
        404 if learning track not found.
    """
    _logger = logging.LoggerAdapter(
        logger, {"learning-track": request.title, "path": "/learning-tracks"}
    )

    _logger.debug("Creating learning track %s", request.title)

    try:
        id_ = await gitlab_api.post_learning_track(request)
        return {"learning_track_id": id_}
    except* ValueError as e:
        _logger.warning(
            "Invalid learning track %s - %s.",
            request.title,
            e.exceptions[0].args[0])
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.exceptions[0].args[0]) from e
    except* gitlab_facade.InvalidFileSizeError as e:
        _logger.warning(
            "Invalid learning track %s - %s.",
            request.title,
            e.exceptions[0].args[0])
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Error while creating learning track."
        ) from e
    except* asyncio.TimeoutError as e:
        _logger.warning(
            "Timeout while creating learning track %s.",
            request.title)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Timeout while creating learning track.",
        ) from e
    except* gitlab_facade.GitlabError as e:
        _logger.exception(
            "Error while creating learning track %s.",
            request.title)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Error while creating learning track.") from e
    except* Exception as e:
        _logger.exception(
            "Error while creating learning track %s.",
            request.title
        )
        _logger.exception(e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Error while creating learning track."
        ) from e


@router.get("/users/{user_id}/progress", status_code=200)
async def get_all_progress(
    user_id: int,
    gitlab_api: Annotated[gitlab_facade.Gitlab,
                          Depends(get_authenticated_gitlab)
                          ]) -> list[gitlab_facade.UserProgress]:

    """ Retrieve all progress for a user.

    Parameter Args:
        user_id: The user id.

    Returns:
        200 if the progress was retrieved successfully.
        404 if user not found.
    """

    _logger = logging.LoggerAdapter(logger,
                                    {"path": "/users/{user_id}/progress/"})

    _logger.debug("Getting all progress for user %s", user_id)

    try:
        return await gitlab_api.get_learning_tracks_progress()

    except ValueError as e:
        _logger.warning("Unable to get user progress.")
        raise HTTPException(
            status_code=400,
            detail=e.args[0]) from e

    except asyncio.TimeoutError as e:
        _logger.warning("Timeout while getting progress for user %s", user_id)
        raise HTTPException(
            status_code=504,
            detail="Timeout while getting progress.") from e


@router.get("/users/{user_id}/progress/{learning_track_id}", status_code=200)
async def get_progress(
    user_id: int,
    learning_track_id: int,
    gitlab_api: Annotated[gitlab_facade.Gitlab,
                          Depends(get_authenticated_gitlab)
                          ]) -> GetProgressResponse:

    """ Retrieve a specific learning track progress by id.

    Parameter Args:
        learning_track_id: The learning track id.

    Returns:
        200 if the learning track progress was retrieved successfully.
        404 if learning track not found.
    """
    _logger = logging.LoggerAdapter(logger,
                                    {"path": "/users/{user_id}/progress/"})

    _logger.debug("Getting all progress for user %s", user_id)

    try:
        progress = await gitlab_api.get_learning_track_progress(
            learning_track_id=learning_track_id)
        return {"progress": progress}

    except asyncio.TimeoutError as e:
        _logger.warning("Timeout while getting progress for user %s", user_id)
        raise HTTPException(
            status_code=504,
            detail="Timeout while getting progress.") from e

    except LookupError as e:
        _logger.debug("User id %s has no recorded progress for learning"
                      "track %s.",
                      user_id, learning_track_id)
        raise HTTPException(
            status_code=404,
            detail=e.args[0]) from e


@router.put("/users/{user_id}/progress/{learning_track_id}", status_code=200)
async def put_progress(
    user_id: int,
    learning_track_id: int,
    request: gitlab_facade.UserProgress,
    gitlab_api: Annotated[gitlab_facade.Gitlab,
                          Depends(get_authenticated_gitlab)
                          ]):

    """Put progress for a user in a learning track.

    Parameter Args:
        user_id: The user id.
        learning_track_id: The learning track id.
        request: The progress to be put.

    Returns:
        200 if the progress was put successfully.
        404 if the learning track was not found.
    """

    _logger = logging.LoggerAdapter(logger,
                                    {"path": "/users/{user_id}/progress/" +
                                        "{learning_track_id}"})
    _logger.debug("Putting progress for user id %s and learning track id %s",
                  user_id, learning_track_id)

    try:
        return await gitlab_api.put_learning_track_progress(learning_track_id,
                                                            request)
    except LookupError as e:
        _logger.debug("Learning track id %s not found", learning_track_id)
        raise HTTPException(
            status_code=404,
            detail=f"Learning track {e.args[0]} not found.") from e

    except asyncio.TimeoutError as e:
        _logger.warning("Timeout while putting progress for user %s", user_id)
        raise HTTPException(
            status_code=504,
            detail="Timeout while putting progress.") from e


@router.post("/learning-tracks/{learning_track_id}/copy", status_code=200)
async def copy_learning_track(
        learning_track_id: int,
        gitlab_api: Annotated[gitlab_facade.Gitlab,
                              Depends(get_authenticated_gitlab)
                              ]) -> CreateLearningTrackResponse:
    """Copy a specific learning track by id.

    Parameter Args:
        learning_track_id: The learning track id.

    Returns:
        200 if the learning track was copied successfully.
        404 if learning track not found.
    """
    _logger = logging.LoggerAdapter(logger,
                                    {"path":
                                     "/learning-tracks/{learning_track_id}/"
                                     "copy/"})
    _logger.debug("Copying learning track id %s", learning_track_id)

    try:
        id_ = await gitlab_api.copy_learning_track(learning_track_id)
        return {"learning_track_id": id_}
    except LookupError as e:
        _logger.debug("Learning track id %s not found", learning_track_id)
        raise HTTPException(
            status_code=404,
            detail=f"Learning track {e.args[0]} not found.") from e

    except asyncio.TimeoutError as e:
        _logger.warning("Timeout while copying learning track %s",
                        learning_track_id)
        raise HTTPException(
            status_code=504,
            detail="Timeout while copying learning track.") from e


@router.post("/learning-tracks/{id}/history/{change_id}", status_code=201)
async def revert_learning_track(
        id: int,
        change_id: str,
        gitlab_api: Annotated[gitlab_facade.Gitlab,
                              Depends(get_authenticated_gitlab)
                              ]):
    """Revert a specific learning track by change_id.

    Parameter Args:
        learning_track_id: The learning track id.
        change_id: The change id to revert to.

    Returns:
        201 if the learning track was reverted successfully.
        404 if learning track not found.
    """
    _logger = logging.LoggerAdapter(logger,
                                    {"path":
                                     f"/learning-tracks/{id}/"
                                     f"history/{change_id}"})

    _logger.debug("Reverting learning track id %s", id)

    try:
        await gitlab_api.revert_learning_track(id, change_id)
    except LookupError as e:
        _logger.debug(
            "Learning track id %s or change id %s not found", id, change_id)
        raise HTTPException(
            status_code=404,
            detail=f"Learning track or change id {e.args[0]} not found."
        ) from e

    except asyncio.TimeoutError as e:
        _logger.warning("Timeout while reverting learning track %s", id)
        raise HTTPException(
            status_code=504,
            detail="Timeout while reverting learning track.") from e


@router.get("/learning-tracks/{learning_track_id}/history", status_code=200)
async def get_learning_track_commits(
    learning_track_id: int,
    gitlab_api: Annotated[
        gitlab_facade.Gitlab,
        Depends(get_authenticated_gitlab)
    ]
) -> list[gitlab_facade.LearningTrackCommit]:
    """Retrieve a specific learning track's commit by id.

    Parameter Args:
        learning_track_id: The learning track id.
        change_id: The commit id.

    Returns:
        200 if the commmit was retrieved successfully.
        404 if learning track not found.
    """
    _logger = logging.LoggerAdapter(
        logger, {"path": f"/learning-tracks/{learning_track_id}/history"}
    )
    _logger.debug(f"Getting commits from learning track {learning_track_id}")

    try:
        learning_track_commits = await gitlab_api.get_learning_track_commits(
            learning_track_id
        )
    except gitlab_facade.GitlabLookupError as e:
        if e.resource_type == gitlab_facade.LookupErrors.learning_track:
            _logger.debug(f"Learning track id {learning_track_id} not found")
            raise HTTPException(status_code=404,
                                detail="Learning track not found.") from e

    return learning_track_commits


@router.get("/learning-tracks/{learning_track_id}/history/{change_id}",
            status_code=200)
async def get_learning_track_history(
    learning_track_id: int,
    change_id: str,
    gitlab_api: Annotated[
        gitlab_facade.Gitlab,
        Depends(get_authenticated_gitlab)
    ]
) -> gitlab_facade.LearningTrackData:
    """Retrieve a specific learning track's commit by id.

    Parameter Args:
        learning_track_id: The learning track id.
        change_id: The commit id.

    Returns:
        200 if the commmit was retrieved successfully.
        404 if learning track not found.
    """
    _logger = logging.LoggerAdapter(
        logger,
        {"path": f"/learning-tracks/{learning_track_id}/history/{change_id}"}
    )
    _logger.debug(
        f"Getting commit id {learning_track_id}"
        "from learning track {learning_track_id}"
    )

    try:
        learning_track = await gitlab_api.get_learning_track(
            learning_track_id,
            change_id=change_id
        )
    except gitlab_facade.GitlabLookupError as e:
        if e.resource_type == gitlab_facade.LookupErrors.commit:
            _logger.debug(f"Commit id {change_id} not found")
            raise HTTPException(status_code=404,
                                detail="Commit not found.") from e

        _logger.debug(f"Learning track id {learning_track_id} not found")
        raise HTTPException(status_code=404,
                            detail="Learning track not found.") from e

    return learning_track


@router.post("/learning-tracks/{learning_track_id}/suggestions",
             status_code=204)
async def post_suggestions(
    learning_track_id: int,
    suggestions: list[gitlab_facade.LearningTrackSuggestion],
    gitlab_api: Annotated[gitlab_facade.Gitlab,
                          Depends(get_authenticated_gitlab)
                          ]):

    """Create a suggestion for a learning track.

    Parameter Args:
        learning_track_id: The learning track id.
        suggestions: The suggestions to create.

    Returns:
        200 if the suggestions were created successfully.
        404 if learning track not found.
    """

    _logger = logging.LoggerAdapter(logger,
                                    {"path": "/learning-tracks/" +
                                     f"{learning_track_id}/suggestions"})

    _logger.debug("Creating suggestion for learning track id %s",
                  learning_track_id)

    try:
        return await gitlab_api.post_suggestions(learning_track_id,
                                                 suggestions)

    except LookupError as e:
        _logger.debug("Learning track id %s not found", learning_track_id)
        raise HTTPException(
            status_code=404,
            detail="Learning track not found.") from e

    except asyncio.TimeoutError as e:
        _logger.warning("Timeout while copying learning track %s",
                        learning_track_id)
        raise HTTPException(
            status_code=504,
            detail="Timeout while copying learning track.") from e

    except gitlab_facade.GitlabError as e:
        _logger.exception(
            "Error getting suggestions for learning track %s.",
            learning_track_id)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Error getting suggestions for learning track.") from e


@router.get("/learning-tracks/{learning_track_id}/suggestions",
            status_code=200)
async def get_suggestions(
    learning_track_id: int,
    gitlab_api: Annotated[gitlab_facade.Gitlab,
                          Depends(get_authenticated_gitlab)
                          ]) -> list[gitlab_facade.LearningTrackSuggestion]:

    """Get open suggestions for a learning track.

    Parameter Args:
        learning_track_id: The learning track id.

    Returns:
        200 if the suggestions were retrieved successfully.
        404 if learning track not found.
    """

    _logger = logging.LoggerAdapter(logger,
                                    {"path": "/learning-tracks/" +
                                     "{learning_track_id}/suggestions"})

    _logger.debug("Getting suggestion for learning track id %s",
                  learning_track_id)

    try:
        return await gitlab_api.get_open_suggestions(learning_track_id)

    except LookupError as e:
        _logger.debug("Learning track id %s not found", learning_track_id)
        raise HTTPException(
            status_code=404,
            detail="Learning track not found.") from e

    except asyncio.TimeoutError as e:
        _logger.warning("Timeout while copying learning track %s",
                        learning_track_id)
        raise HTTPException(
            status_code=504,
            detail="Timeout while copying learning track.") from e

    except gitlab_facade.GitlabError as e:
        _logger.exception(
            "Error getting suggestions for learning track %s.",
            learning_track_id)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Error getting suggestions for learning track.") from e


@router.patch("/learning-tracks/{learning_track_id}", status_code=204)
async def edit_learning_track(
        learning_track_id: int,
        patch: Annotated[list, Body()],
        gitlab_api: Annotated[gitlab_facade.Gitlab,
                              Depends(get_authenticated_gitlab)
                              ]) -> None:
    """Edit a specific learning track by id.

    Parameter Args:
        learning_track_id: The learning track id.
        patch: The patch containing the diffs.

    Returns:
        200 if the learning track was edited successfully.
        404 if learning track not found.
    """
    _logger = logging.LoggerAdapter(logger,
                                    {"path":
                                     "/learning-tracks/{learning_track_id}"})
    _logger.debug("Editing learning track id %s", learning_track_id)

    if not patch:
        return status.HTTP_204_NO_CONTENT

    try:
        await gitlab_api.edit_learning_track(learning_track_id, patch)
        return status.HTTP_204_NO_CONTENT

    except asyncio.TimeoutError as e:
        _logger.warning("Timeout while editing learning track %s",
                        learning_track_id)
        raise HTTPException(
            status_code=504,
            detail="Timeout while editing learning track.") from e

    except LookupError as e:
        _logger.debug("Learning track %s not found",
                      learning_track_id)
        raise HTTPException(
            status_code=404,
            detail="Learning track not found.") from e


@router.put("/learning-tracks/{learning_track_id}/suggestions/{suggestion_id}",
            status_code=201)
async def manage_suggestion(
    action: str,
    learning_track_id: int,
    suggestion_id: str,
    gitlab_api: Annotated[gitlab_facade.Gitlab,
                          Depends(get_authenticated_gitlab)
                          ]):

    """Manage a suggestion for a learning track.

    Parameter Args:
        action: The action to perform on the suggestion (Available values:
        reject, approve).
        learning_track_id: The learning track id.
        suggestion_id: The suggestion id.

    Returns:
        201 if the suggestion was managed successfully.
        404 if learning track or suggestion not found.
    """

    _logger = logging.LoggerAdapter(logger,
                                    {"path": "/learning-tracks/"
                                     f"{learning_track_id}/suggestions/"
                                     f"{suggestion_id}"})

    _logger.debug("Managing suggestion %s for learning track id %s",
                  suggestion_id, learning_track_id)

    try:
        if action == "reject" or action == "approve":
            await gitlab_api.manage_suggestion(learning_track_id,
                                               suggestion_id, action)
        else:
            raise HTTPException(
                status_code=400,
                detail="Action not supported.")

    except LookupError as e:
        _logger.debug("Learning track id %s or suggestion id %s not found",
                      learning_track_id, suggestion_id)
        raise HTTPException(
            status_code=404,
            detail="Learning track or suggestion not found.") from e

    except asyncio.TimeoutError as e:
        _logger.warning("Timeout while managing suggestion %s for learning "
                        "track %s",
                        suggestion_id, learning_track_id)
        raise HTTPException(
            status_code=504,
            detail="Timeout while managing suggestion.") from e

    except gitlab_facade.GitlabError as e:
        _logger.exception(
            "Error managing suggestion %s for learning track %s.",
            suggestion_id, learning_track_id)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Error managing suggestion.") from e


@router.delete("/learning-tracks/{learning_track_id}", status_code=204)
async def delete_learning_track(
        learning_track_id: int,
        gitlab_api: Annotated[gitlab_facade.Gitlab,
                              Depends(get_authenticated_gitlab)
                              ]) -> None:
    """Delete a specific learning track by id.

    Parameter Args:
        learning_track_id: The learning track id.

    Returns:
        204 if the learning track was deleted successfully.
        404 if learning track not found.
    """
    _logger = logging.LoggerAdapter(logger,
                                    {"path":
                                     "/learning-tracks/{learning_track_id}"})
    _logger.debug("Deleting learning track id %s", learning_track_id)

    try:
        await gitlab_api.delete_learning_track(learning_track_id)

    except asyncio.TimeoutError as e:
        _logger.warning("Timeout while deleting learning track %s",
                        learning_track_id)
        raise HTTPException(
            status_code=504,
            detail="Timeout while deleting learning track.") from e

    except LookupError as e:
        _logger.debug("Learning track %s not found",
                      learning_track_id)
        raise HTTPException(
            status_code=404,
            detail="Learning track not found.") from e

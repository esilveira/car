import base64
import datetime
from json import dumps
import os
from types import SimpleNamespace
from typing import cast
from unittest import IsolatedAsyncioTestCase, TestCase, mock
from unittest.mock import patch
from urllib.parse import urljoin

from aiohttp import ClientSession
import jwt
import json

from app.gitlab_facade import (
    Gitlab, GitlabConfig, LearningTrackMetadata, LevelEnum, GitlabError,
    ResourceProgress, ResourceTypeEnum, UserInfo, LearningTrackData, Creator,
    Lesson, Resource, AllLearningTracks, UserProgress, LearningTrackCommit,
    GitlabImage)

from app import gitlab_facade
from tests.mock_session import FakeResponse, FakeSession

TEST_HOSTNAME = "http://localhost:8080"


class GitlabMixin(TestCase):
    def setUp(self):
        super().setUp()
        self.fake_session = FakeSession()
        self.gitlab = Gitlab(
            config=GitlabConfig(gitlab_hostname=TEST_HOSTNAME),
            session=cast(ClientSession, self.fake_session))
        Gitlab._rsa_cache.clear()

    def endpoint(self, path):
        return f"{TEST_HOSTNAME}{path}"


def approx_date(date1: datetime.datetime,
                date2: datetime.datetime | None = None, /,
                delta: datetime.timedelta = datetime.timedelta(seconds=5)
                ) -> bool | None:
    """Check if two dates are approximately equal.

    Args:
        date1: First date.
        date2: Second date. Defaults to now.
        delta: Maximum difference between dates.

    Returns:
        True if the dates are approximately equal, False otherwise.
    """
    return (date1 - delta <
            (date2 or datetime.datetime.now(datetime.UTC)) <
            date1 + delta)


class GitlabLoginTestCase(GitlabMixin, IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.jwk_patcher = patch("app.gitlab_facade.PyJWKClient",
                                 autospec=True, spec_set=True)
        self.decode_patcher = patch("app.gitlab_facade.jwt_decode",
                                    autospec=True,
                                    spec_set=True)
        self.jwk_client = self.jwk_patcher.start()
        self.jwk_client.return_value.get_signing_key_from_jwt.return_value = (
            SimpleNamespace(key="test_key"))

        self.jwt_decode = self.decode_patcher.start()
        self.jwt_decode.return_value = {
            "sub": 1337,
            "name": "test_name",
            "preferred_username": "test_username",
            "email": "test_email"
        }
        self.fake_session.responses.append(
            FakeResponse(
                status=200,
                body_dict={
                    "access_token": "test_access",
                    "token_type": "bearer",
                    "refresh_token": "test_refresh",
                    "expires_in": 3600,
                    "id_token": "quim barreiros"})
        )

    def tearDown(self):
        super().tearDown()
        self.jwk_patcher.stop()
        self.decode_patcher.stop()

    async def test_login(self):
        """Test login to Gitlab, with a successful response."""

        token, user_info = await self.gitlab.login(
            username="username",
            password="password")

        self.assertEqual(token.access_token, "test_access")
        self.assertEqual(token.token_type, "bearer")
        self.assertEqual(token.refresh_token, "test_refresh")

        assert approx_date(
            token.expiration_date,
            datetime.datetime.now(datetime.UTC) +
            datetime.timedelta(seconds=3600))

        request = self.fake_session.requests.pop()

        self.assertEqual(set(request.data.pop("scope").split(" ")),
                         {"api", "email", "openid"})

        self.assertEqual(request.data,
                         {'grant_type': 'password',
                          'password': 'password',
                          'username': 'username'})

        self.assertEqual(request.url, urljoin(TEST_HOSTNAME, "/oauth/token"))

        self.jwk_client.assert_called_once_with(
            self.endpoint("/oauth/discovery/keys"),
            cache_keys=True,
            lifespan=mock.ANY)
        self.jwt_decode.assert_called_once_with(
            "quim barreiros",
            algorithms=Gitlab._JWT_ALGORITHMS,
            key="test_key")

        expected_info = UserInfo(id=1337,
                                 name="test_name",
                                 username="test_username",
                                 email="test_email")

        self.assertEqual(expected_info, user_info)

    async def test_invalid_jwt_configuration(self):
        self.jwk_client.return_value.get_signing_key_from_jwt.side_effect = (
            jwt.PyJWKClientError)

        with self.assertRaisesRegex(gitlab_facade.GitlabError, ".*JWT token"):
            await self.gitlab.login(username="asd", password="asd")

    async def test_invalid_jwt_token(self):
        self.jwt_decode.side_effect = jwt.InvalidTokenError()

        with self.assertRaisesRegex(gitlab_facade.GitlabError, ".*JWT token"):
            await self.gitlab.login(username="asd", password="asd")

    async def test_login_bad_credentials(self):
        """Incorrect credentials"""
        self.fake_session.responses.appendleft(FakeResponse(400))

        with self.assertRaisesRegex(
            gitlab_facade.GitlabError,
            ".*credentials"
        ):
            await self.gitlab.login(username="asd", password="asd")

    async def test_login_gitlab_error(self):
        self.fake_session.responses.appendleft(FakeResponse(500))

        with self.assertRaisesRegex(gitlab_facade.GitlabError,
                                    "Gitlab returned status code 500"):
            await self.gitlab.login(username="asd", password="asd")

    async def test_gitlab_returns_invalid_data(self):
        self.fake_session.responses.appendleft(FakeResponse(
            200, body_dict={"access_token": "test_access"}))

        with self.assertRaisesRegex(gitlab_facade.GitlabError,
                                    "Invalid data returned by Gitlab"):
            await self.gitlab.login(username="asd", password="asd")


class GitlabRegisterTestCase(GitlabMixin, IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.gitlab.access_token = "test_access"

    async def test_register_success(self):
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={})
        )
        info = gitlab_facade.RegisterData(
            username="test",
            password="password",
            name="Test User",
            email="test@example.com"
        )
        await self.gitlab.register(info)

        request = self.fake_session.requests.pop()

        self.assertEqual(request.url, urljoin(TEST_HOSTNAME, "/api/v4/users"))

        self.assertEqual(request.data, {
            "username": "test",
            "password": "password",
            "name": "Test User",
            "email": "test@example.com"
        })

    async def test_register_gitlab_username_exists(self):
        """Gitlab returns 409 when username already exists"""
        self.fake_session.responses.append(
            FakeResponse(status=409,
                         body_dict={
                             "message": "Username has already been taken"})
        )
        info = gitlab_facade.RegisterData(
            username="test",
            password="password",
            name="Test User",
            email="test@example.com"
        )
        with self.assertRaisesRegex(
                gitlab_facade.EntityAlreadyExists, "username") as cm:
            await self.gitlab.register(info)

        self.assertEqual(cm.exception.entity, "test")

    async def test_register_gitlab_email_exists(self):
        """Gitlab returns 409 when email already exists"""
        self.fake_session.responses.append(
            FakeResponse(status=409,
                         body_dict={"message": "Email has already been taken"})
        )
        info = gitlab_facade.RegisterData(
            username="test",
            password="password",
            name="Test User",
            email="test@example.com"
        )

        with self.assertRaisesRegex(
            gitlab_facade.EntityAlreadyExists,
            "email"
        ) as cm:
            await self.gitlab.register(info)

        self.assertEqual(cm.exception.entity, "test@example.com")

    async def test_register_gitlab_409(self):
        """Gitlab returns 409"""
        self.fake_session.responses.append(
            FakeResponse(status=409,
                         body_dict={"message": "abc"})
        )
        info = gitlab_facade.RegisterData(
            username="test",
            password="password",
            name="Test User",
            email="test@example.com"
        )

        with self.assertRaisesRegex(
            gitlab_facade._ClientResponseBodyError,
            "409"
        ):
            await self.gitlab.register(info)

    async def test_register_gitlab_401(self):
        """Gitlab returns 401"""
        self.fake_session.responses.append(
            FakeResponse(status=401,
                         body_dict={"message": "abc"})
        )
        info = gitlab_facade.RegisterData(
            username="test",
            password="password",
            name="Test User",
            email="test@example.com"
        )

        with self.assertRaisesRegex(gitlab_facade.Unauthorized, ""):
            await self.gitlab.register(info)

    async def test_register_invalid_password(self):
        """Gitlab returns 400 when password is too short"""
        self.fake_session.responses.append(
            FakeResponse(
                status=400,
                body_dict={
                    "message":
                    dict(
                        password=["is too short (minimum is 8 characters)"])})
        )
        info = gitlab_facade.RegisterData(
            username="test",
            password="password",
            name="Test User",
            email="test@example.com"
        )

        with self.assertRaisesRegex(ValueError, "is too short"):
            await self.gitlab.register(info)

    async def test_register_invalid_data(self):
        """Gitlab returns 400 when data is invalid"""
        self.fake_session.responses.append(
            FakeResponse(status=400,
                         body_dict={"message": {}})
        )
        info = gitlab_facade.RegisterData(
            username="test",
            password="password",
            name="Test User",
            email="test@example.com"
        )

        with self.assertRaisesRegex(ValueError, "Invalid data"):
            await self.gitlab.register(info)

    async def test_register_gitlab_error(self):
        """Gitlab returns 500 when something goes wrong"""
        self.fake_session.responses.append(
            FakeResponse(status=500)
        )
        info = gitlab_facade.RegisterData(
            username="test",
            password="password",
            name="Test User",
            email="test@example.com"
        )

        with self.assertRaisesRegex(
                gitlab_facade.GitlabError, "Gitlab returned status code 500"):
            await self.gitlab.register(info)


class GitlabGetLearningTrackTestCase(GitlabMixin, IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.gitlab.access_token = "test_access"

    async def test_get_learning_track_success(self):
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_name": "track.json",
                "file_path": "track.json",
                "size": 2121,
                "encoding": "base64",
                "content_sha256": "d142e040117e680aafe515a53a33f4baeb49fc38953"
                "5edeb91869a917b173571",
                "ref": "main",
                "blob_id": "f5443b5921eb1b4fa4367eaffa17532b213d47b2",
                "commit_id": "d6fa002403c8515afe0d0f215cfdf7f2631ef518",
                "last_commit_id": "d6fa002403c8515afe0d0f215cfdf7f2631ef518",
                "execute_filemode": "false",
                "content": "ewoJImNhcmVlcl9wYXRoIjogInNvbWVDYXJlZXJQYXRoIiw"
                "KCSJsZXZlbCI6ICJleHBlcnQiLAoJInNraWxscyI6ICJza2lsbHMiL"
                "AoJImxlc3NvbnMiOiBbewoJCSJsZXNzb25faWQiOiAic29tZVVVSUQ"
                "iLAoJCSJuYW1lIjogInNvbWVOYW1lIiwKCQkicmVzb3VyY2VzIjogW3"
                "sKCQkJCSJsaW5rIjogImh0dHA6Ly8uc29tZWxpbmsuY29tIiwKCQkJC"
                "SJyZXNvdXJjZV9pZCI6ICJzb21lVVVJRCIsCgkJCQkidGl0bGUiOiAi"
                "c29tZVRpdGxlIiwKCQkJCSJzb3VyY2UiOiAic29tZVRpdGxlIiwKCQkJ"
                "CSJyZXNvdXJjZV90eXBlIjogImJvb2siLAoJCQkJImR1cmF0aW9uIjog"
                "MTAsCgkJCQkiYWRkZWRCeSI6ICJxdWltYmFycmVpcm9zIgoJCQl9LAoJ"
                "CQl7CgkJCQkibGluayI6ICJodHRwOi8vLnNvbWVsaW5rLmNvbSIsCgkJ"
                "CQkicmVzb3VyY2VfaWQiOiAic29tZVVVSUQiLAoJCQkJInRpdGxlIjog"
                "InNvbWVUaXRsZSIsCgkJCQkic291cmNlIjogInNvbWVUaXRsZSIsCgkJ"
                "CQkicmVzb3VyY2VfdHlwZSI6ICJib29rIiwKCQkJCSJkdXJhdGlvbiI6"
                "IDEwLAoJCQkJImFkZGVkQnkiOiAicXVpbWJhcnJlaXJvcyIKCQkJfQoJ"
                "CV0KCgl9XQp9"
            }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 12345,
                "builds_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\", \"career_path\": \"string3\", \"level\"" +
                ": \"expert\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": "https://i.postimg.cc/wM8xN4pv/animals-" +
                "pixelated-very-small-16x16-v0-aatcct01bfoa1.jpg",
            }))

        current_dir = os.path.dirname(os.path.abspath(__file__))
        image_path = os.path.join(current_dir, "images/animals-pixelated.png")
        # with open(image_path, "rb") as image:
        image = open(image_path, "rb")
        # thumbnail_image = BytesIO(image.read())
        thumbnail_image = image.read()
        image.close()

        # thumbnail_image = image
        # size = image.read()
        # thumbnail_image.seek(0)

        self.fake_session.responses.append(
            FakeResponse(
                status=200, body=thumbnail_image,
                content_type="image/png",
                content_length=len(thumbnail_image)
            )
        )

        result = await self.gitlab.get_learning_track("12345")

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "GET")

        self.assertEqual(
            request.url,
            "https://i.postimg.cc/wM8xN4pv/animals-pixelated-very-small-16x16-v0-aatcct01bfoa1.jpg"  # noqa: E501
        )

        # self.assertEqual(request.url, urljoin(
        #     TEST_HOSTNAME, "/api/v4/projects/12345"))

        expected = LearningTrackData(
            learning_track_id=12345,
            is_draft=False,
            is_private=True,
            title='str1',
            career='string2',
            career_path='string3',
            description='string1',
            thumbnail_image="data:image/jpg;base64," +
            "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAA" +
            "BccqhmAAADA0lEQVR42u3csY2DMBSA4eMUUTEJ" +
            "k1CwAQOxAQsgNqAwA1C7YwBmoCcDXLp3kiXyff" +
            "0TiUN+ubGrnPP9A3ylX0sAAgAIACAAgAAAAgAI" +
            "ACAAgAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAA" +
            "gAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAAgAAAA" +
            "gAIACAAgACAAAACAAgAIACAAAACAAgAIACAAAACAAg" +
            "AIACAAAACAAgAIACAAAACAAgAIACAAAACAAgAIACAAA" +
            "ACAAgAIACAAAACAAgAIACAAAACAAgAIACAAIAAAAIACAAgAIAAAE" +
            "/2sgRlLcsSmh+GwefHDgAQAEAAAAEABAAQAEAAAAEABAAEABAAQAA" +
            "AAQAEABAA4HncB1BYXdeh+eh5/NKfHzsAQAAAAQAEABAAQAAAAQAE" +
            "ABAAQAAAAQAEABAAQAAAAQA+ch9AUPQ8/r7vofl1XUPzfd8Xff55" +
            "nl4iOwBAAAABAAQAEABAAAABAAQAEABAAAABAAQAEABAAAABAP6q" +
            "cs63ZSgnep9AVNM0RZ+/bVtofpomL5EdACAAgAAAAgAIACAAgAAA" +
            "AgAIAAgAIACAAAACAAgAIADAE70sQVkppdB813Wh+eu6in5/5/nt" +
            "AAABAAQAEABAAAABAAQAEABAAAABAAQAEABAAAABAAQA+Mh9AEH" +
            "jOIbmo+f5m6bxI2AHAAgAIACAAAACAAgAIACAAAACAAIACAAgA" +
            "IAAAAIACADwPF9/H8CyLEWfn1IKzbdtG5o/jiM0P8+zf5EdACAA" +
            "gAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAAgAAA/6/KOd+WAew" +
            "AAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAA" +
            "EABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEAB" +
            "AAQABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAE" +
            "ABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQCC3vIiOZAJf1Z6AA" +
            "AAAElFTkSuQmCC",
            level='expert',
            tags=['string'],
            skills='skills',
            createdBy=Creator(
                username='antonio',
                name='antonio antonio',
                avatar="https://www.gravatar.com/avatar/"
                "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                creator_id=15),
            lessons=[
                Lesson(lesson_id='someUUID',
                       name='someName',
                       resources=[
                                 Resource(resource_id='someUUID',
                                          link='http://.somelink.com',
                                          title='someTitle',
                                          source='someTitle',
                                          resource_type='book',
                                          duration=10,
                                          addedBy='quimbarreiros'),
                                 Resource(resource_id='someUUID',
                                          link='http://.somelink.com',
                                          title='someTitle',
                                          source='someTitle',
                                          resource_type='book',
                                          duration=10,
                                          addedBy='quimbarreiros')])])

        self.assertEqual(result, expected)

    async def test_learning_track_gitlab_error(self):
        """Gitlab returns 500 when something goes wrong"""
        self.fake_session.responses.append(
            FakeResponse(status=500)
        )

        with self.assertRaisesRegex(
                gitlab_facade.GitlabError, "Gitlab returned status code 500"):
            await self.gitlab.get_learning_track("12345")

    async def test_learning_track_gitlab_401(self):
        """Gitlab returns 401"""
        self.fake_session.responses.append(
            FakeResponse(status=401)
        )

        with self.assertRaisesRegex(
            expected_exception=gitlab_facade.Unauthorized,
            expected_regex=""
        ):
            await self.gitlab.get_learning_track("12345")

    async def test_learning_track_gitlab_404(self):
        """Gitlab returns 404"""
        self.fake_session.responses.append(
            FakeResponse(status=404)
        )

        with self.assertRaises(gitlab_facade.GitlabLookupError):
            await self.gitlab.get_learning_track("123456")

    async def test_all_learning_track_gitlab_success(self):
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict=[
                {
                    "id": 164,
                    "description":
                    "{\"description\": \"someDescription\", \"career\":"
                        " \"someCareer\", \"career_path\"" +
                        ": \"someCareerPath\",\"level\": \"expert\"}",
                    "name": "1234567891 3d6edd",
                    "name_with_namespace": "Administrator / 1234567891 3d6edd",
                    "path": "1234567891-3d6edd",
                    "path_with_namespace": "root/1234567891-3d6edd",
                    "created_at": "2023-07-03T21:46:21.768Z",
                    "default_branch": "main",
                    "tag_list": [
                            "one",
                            "two"
                    ],
                    "topics": [
                        "one",
                        "two"
                    ],
                    "forks_count": 0,
                    "avatar_url": "https://i.postimg.cc/wM8xN4pv/animals" +
                    "-pixelated-very-small-16x16-v0-aatcct01bfoa1.jpg",
                    "star_count": 0,
                    "last_activity_at": "2023-07-03T21:46:21.768Z",
                    "packages_enabled": True,
                    "empty_repo": False,
                    "archived": False,
                    "visibility": "public",
                    "owner": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/",
                        "web_url": "http://gitlab.example.com/root"
                    },
                    "resolve_outdated_diff_discussions": False,
                    "issues_enabled": True,
                    "merge_requests_enabled": True,
                    "wiki_enabled": True,
                    "jobs_enabled": True,
                    "snippets_enabled": True,
                    "container_registry_enabled": True,
                    "service_desk_enabled": False,
                    "can_create_merge_request_in": True,
                    "issues_access_level": "enabled",
                    "repository_access_level": "enabled",
                    "merge_requests_access_level": "enabled",
                    "forking_access_level": "enabled",
                    "wiki_access_level": "enabled",
                    "builds_access_level": "enabled",
                    "snippets_access_level": "enabled",
                    "pages_access_level": "private",
                    "analytics_access_level": "enabled",
                    "container_registry_access_level": "enabled",
                    "security_and_compliance_access_level": "private",
                    "releases_access_level": "enabled",
                    "environments_access_level": "enabled",
                    "feature_flags_access_level": "enabled",
                    "infrastructure_access_level": "enabled",
                    "monitor_access_level": "enabled",
                    "shared_runners_enabled": True,
                    "lfs_enabled": True,
                    "creator_id": 1,
                    "import_status": "none",
                    "open_issues_count": 0,
                    "updated_at": "2023-07-03T21:46:23.641Z",
                    "ci_default_git_depth": 20,
                    "ci_forward_deployment_enabled": True,
                    "ci_job_token_scope_enabled": False,
                    "ci_separated_caches": True,
                    "build_git_strategy": "fetch",
                    "keep_latest_artifact": True,
                    "restrict_user_defined_variables": False,
                    "runners_token": "GR1348941nnsUYoeJZP-sA9fepw6X",
                    "group_runners_enabled": True,
                    "auto_cancel_pending_pipelines": "enabled",
                    "build_timeout": 3600,
                    "auto_devops_enabled": True,
                    "auto_devops_deploy_strategy": "continuous",
                    "public_jobs": True,
                    "only_allow_merge_if_pipeline_succeeds": False,
                    "request_access_enabled": True,
                    "remove_source_branch_after_merge": True,
                    "printing_merge_request_link_enabled": True,
                    "merge_method": "merge",
                    "squash_option": "default_off",
                    "enforce_auth_checks_on_uploads": True,
                    "autoclose_referenced_issues": True,
                    "repository_storage": "default"
                }
            ]
            ))

        result = await self.gitlab.get_learning_tracks("some")

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "GET")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/projects?search=some"))
        expected = AllLearningTracks(
            learning_tracks=[
                LearningTrackMetadata(
                    learning_track_id=164,
                    title='1234567891',
                    is_draft=False,
                    is_private=False,
                    career='someCareer',
                    career_path='someCareerPath',
                    description='someDescription',
                    thumbnail_image="data:image/jpg;base64," +
                    "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAA" +
                    "BccqhmAAADA0lEQVR42u3csY2DMBSA4eMUUTEJ" +
                    "k1CwAQOxAQsgNqAwA1C7YwBmoCcDXLp3kiXyff" +
                    "0TiUN+ubGrnPP9A3ylX0sAAgAIACAAgAAAAgAI" +
                    "ACAAgAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAA" +
                    "gAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAAgAAAA" +
                    "gAIACAAgACAAAACAAgAIACAAAACAAgAIACAAAACAAg" +
                    "AIACAAAACAAgAIACAAAACAAgAIACAAAACAAgAIACAAA" +
                    "ACAAgAIACAAAACAAgAIACAAAACAAgAIACAAIAAAAIACAAgAIAAAE" +
                    "/2sgRlLcsSmh+GwefHDgAQAEAAAAEABAAQAEAAAAEABAAEABAAQAA" +
                    "AAQAEABAA4HncB1BYXdeh+eh5/NKfHzsAQAAAAQAEABAAQAAAAQAE" +
                    "ABAAQAAAAQAEABAAQAAAAQA+ch9AUPQ8/r7vofl1XUPzfd8Xff55" +
                    "nl4iOwBAAAABAAQAEABAAAABAAQAEABAAAABAAQAEABAAAABAP6q" +
                    "cs63ZSgnep9AVNM0RZ+/bVtofpomL5EdACAAgAAAAgAIACAAgAAA" +
                    "AgAIAAgAIACAAAACAAgAIADAE70sQVkppdB813Wh+eu6in5/5/nt" +
                    "AAABAAQAEABAAAABAAQAEABAAAABAAQAEABAAAABAAQA+Mh9AEH" +
                    "jOIbmo+f5m6bxI2AHAAgAIACAAAACAAgAIACAAAACAAIACAAgA" +
                    "IAAAAIACADwPF9/H8CyLEWfn1IKzbdtG5o/jiM0P8+zf5EdACAA" +
                    "gAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAAgAAA/6/KOd+WAew" +
                    "AAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAA" +
                    "EABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEAB" +
                    "AAQABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAE" +
                    "ABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQCC3vIiOZAJf1Z6AA" +
                    "AAAElFTkSuQmCC",
                    level='expert',
                    tags=['one', 'two'],
                    createdBy=Creator(
                        name='Administrator',
                        avatar='https://www.gravatar.com/avatar/',
                        username='root',
                        creator_id=1
                    )
                )
            ],
            hasResults=True
        )

        self.assertEqual(result, expected)

    async def test_all_learning_track_gitlab_success_has_results_false(self):
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={}))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict=[
                {
                    "id": 164,
                    "description":
                    "{\"description\": \"someDescription\", \"career\":"
                        " \"someCareer\", \"career_path\"" +
                        ": \"someCareerPath\",\"level\": \"expert\"}",
                    "name": "1234567891 3d6edd",
                    "name_with_namespace": "Administrator / 1234567891 3d6edd",
                    "path": "1234567891-3d6edd",
                    "path_with_namespace": "root/1234567891-3d6edd",
                    "created_at": "2023-07-03T21:46:21.768Z",
                    "default_branch": "main",
                    "tag_list": [
                            "one",
                            "two"
                    ],
                    "topics": [
                        "one",
                        "two"
                    ],
                    "forks_count": 0,
                    "avatar_url": "https://i.postimg.cc/wM8xN4pv/animals-" +
                    "pixelated-very-small-16x16-v0-aatcct01bfoa1.jpg",
                    "star_count": 0,
                    "last_activity_at": "2023-07-03T21:46:21.768Z",
                    "packages_enabled": True,
                    "empty_repo": False,
                    "archived": False,
                    "visibility": "public",
                    "owner": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/",
                        "web_url": "http://gitlab.example.com/root"
                    },
                    "resolve_outdated_diff_discussions": False,
                    "issues_enabled": True,
                    "merge_requests_enabled": True,
                    "wiki_enabled": True,
                    "jobs_enabled": True,
                    "snippets_enabled": True,
                    "container_registry_enabled": True,
                    "service_desk_enabled": False,
                    "can_create_merge_request_in": True,
                    "issues_access_level": "enabled",
                    "repository_access_level": "enabled",
                    "merge_requests_access_level": "enabled",
                    "forking_access_level": "enabled",
                    "wiki_access_level": "enabled",
                    "builds_access_level": "enabled",
                    "snippets_access_level": "enabled",
                    "pages_access_level": "private",
                    "analytics_access_level": "enabled",
                    "container_registry_access_level": "enabled",
                    "security_and_compliance_access_level": "private",
                    "releases_access_level": "enabled",
                    "environments_access_level": "enabled",
                    "feature_flags_access_level": "enabled",
                    "infrastructure_access_level": "enabled",
                    "monitor_access_level": "enabled",
                    "shared_runners_enabled": True,
                    "lfs_enabled": True,
                    "creator_id": 1,
                    "import_status": "none",
                    "open_issues_count": 0,
                    "updated_at": "2023-07-03T21:46:23.641Z",
                    "ci_default_git_depth": 20,
                    "ci_forward_deployment_enabled": True,
                    "ci_job_token_scope_enabled": False,
                    "ci_separated_caches": True,
                    "build_git_strategy": "fetch",
                    "keep_latest_artifact": True,
                    "restrict_user_defined_variables": False,
                    "runners_token": "GR1348941nnsUYoeJZP-sA9fepw6X",
                    "group_runners_enabled": True,
                    "auto_cancel_pending_pipelines": "enabled",
                    "build_timeout": 3600,
                    "auto_devops_enabled": True,
                    "auto_devops_deploy_strategy": "continuous",
                    "public_jobs": True,
                    "only_allow_merge_if_pipeline_succeeds": False,
                    "request_access_enabled": True,
                    "remove_source_branch_after_merge": True,
                    "printing_merge_request_link_enabled": True,
                    "merge_method": "merge",
                    "squash_option": "default_off",
                    "enforce_auth_checks_on_uploads": True,
                    "autoclose_referenced_issues": True,
                    "repository_storage": "default"
                }
            ]
            ))

        result = await self.gitlab.get_learning_tracks("some")

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "GET")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/projects"))
        expected = AllLearningTracks(
            learning_tracks=[
                LearningTrackMetadata(
                    learning_track_id=164,
                    title='1234567891',
                    is_draft=False,
                    is_private=False,
                    career='someCareer',
                    career_path='someCareerPath',
                    description='someDescription',
                    thumbnail_image="data:image/jpg;base64," +
                    "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAA" +
                    "BccqhmAAADA0lEQVR42u3csY2DMBSA4eMUUTEJ" +
                    "k1CwAQOxAQsgNqAwA1C7YwBmoCcDXLp3kiXyff" +
                    "0TiUN+ubGrnPP9A3ylX0sAAgAIACAAgAAAAgAI" +
                    "ACAAgAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAA" +
                    "gAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAAgAAAA" +
                    "gAIACAAgACAAAACAAgAIACAAAACAAgAIACAAAACAAg" +
                    "AIACAAAACAAgAIACAAAACAAgAIACAAAACAAgAIACAAA" +
                    "ACAAgAIACAAAACAAgAIACAAAACAAgAIACAAIAAAAIACAAgAIAAAE" +
                    "/2sgRlLcsSmh+GwefHDgAQAEAAAAEABAAQAEAAAAEABAAEABAAQAA" +
                    "AAQAEABAA4HncB1BYXdeh+eh5/NKfHzsAQAAAAQAEABAAQAAAAQAE" +
                    "ABAAQAAAAQAEABAAQAAAAQA+ch9AUPQ8/r7vofl1XUPzfd8Xff55" +
                    "nl4iOwBAAAABAAQAEABAAAABAAQAEABAAAABAAQAEABAAAABAP6q" +
                    "cs63ZSgnep9AVNM0RZ+/bVtofpomL5EdACAAgAAAAgAIACAAgAAA" +
                    "AgAIAAgAIACAAAACAAgAIADAE70sQVkppdB813Wh+eu6in5/5/nt" +
                    "AAABAAQAEABAAAABAAQAEABAAAABAAQAEABAAAABAAQA+Mh9AEH" +
                    "jOIbmo+f5m6bxI2AHAAgAIACAAAACAAgAIACAAAACAAIACAAgA" +
                    "IAAAAIACADwPF9/H8CyLEWfn1IKzbdtG5o/jiM0P8+zf5EdACAA" +
                    "gAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAAgAAA/6/KOd+WAew" +
                    "AAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAA" +
                    "EABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEAB" +
                    "AAQABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAE" +
                    "ABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQCC3vIiOZAJf1Z6AA" +
                    "AAAElFTkSuQmCC",
                    level='expert',
                    tags=['one', 'two'],
                    createdBy=Creator(
                        name='Administrator',
                        avatar='https://www.gravatar.com/avatar/',
                        username='root',
                        creator_id=1
                    )
                )
            ],
            hasResults=False
        )

        self.assertEqual(result, expected)

    async def test_all_learning_track_gitlab_error(self):
        """Gitlab returns 500 when something goes wrong"""
        self.fake_session.responses.append(
            FakeResponse(status=500)
        )

        with self.assertRaisesRegex(
                gitlab_facade.GitlabError, "Gitlab returned status code 500"):
            await self.gitlab.get_learning_tracks("some")

    async def test_all_learning_track_gitlab_401(self):
        """Gitlab returns 401"""
        self.fake_session.responses.append(
            FakeResponse(status=401)
        )

        with self.assertRaisesRegex(
            expected_exception=gitlab_facade.Unauthorized,
            expected_regex=""
        ):
            await self.gitlab.get_learning_track("some")


class GitlabPostLearningTrackTestCase(GitlabMixin, IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.gitlab.access_token = "test_access"

        # Get the directory path of the current file
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Construct the path to the image file
        image_path = os.path.join(current_dir, "images/image.jpg")
        image = open(image_path, "rb")
        thumbnail_image = base64.b64encode(image.read()).decode('utf-8')
        image.close()

        self.learning_track = gitlab_facade.LearningTrackData(
            learning_track_id=12345,
            is_draft=False,
            is_private=True,
            title='str1',
            career='string2',
            career_path='someCareerPath',
            description='string1',
            thumbnail_image=thumbnail_image,
            level=LevelEnum.expert,
            tags=['string'],
            skills='skills',
            createdBy=gitlab_facade.Creator(
                username='antonio',
                name='antonio antonio',
                avatar="https://www.gravatar.com/avatar/"
                "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                creator_id=15),
            lessons=[
                gitlab_facade.Lesson(
                    lesson_id='someUUID',
                    name='someName',
                    resources=[
                        gitlab_facade.Resource(
                            resource_id='someUUID',
                            link='http://.somelink.com',
                            title='someTitle',
                            source='someTitle',
                            resource_type=ResourceTypeEnum.book,
                            duration=10,
                            addedBy='quimbarreiros'
                        )
                    ]
                )
            ]
        )

        self.learning_track_invalid_image = gitlab_facade.LearningTrackData(
            learning_track_id=12345,
            is_draft=False,
            is_private=True,
            title='str1',
            career='string2',
            career_path='someCareerPath',
            description='string1',
            thumbnail_image="bananas",
            level=LevelEnum.expert,
            tags=['string'],
            skills='skills',
            createdBy=gitlab_facade.Creator(
                username='antonio',
                name='antonio antonio',
                avatar="https://www.gravatar.com/avatar/"
                "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                creator_id=15),
            lessons=[
                gitlab_facade.Lesson(
                    lesson_id='someUUID',
                    name='someName',
                    resources=[
                        gitlab_facade.Resource(
                            resource_id='someUUID',
                            link='http://.somelink.com',
                            title='someTitle',
                            source='someTitle',
                            resource_type=ResourceTypeEnum.book,
                            duration=10,
                            addedBy='quimbarreiros'
                        )
                    ]
                )
            ]
        )

    async def test_post_learning_track_success(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "string1",
                "career": "string2",
                "name": "str1 123456",
                "career_path": "someCareerPath",
                "level": "expert",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "string1",
                "career": "string2",
                "career_path": "someCareerPath",
                "level": "expert",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": "https://www.gravatar.com/avatar/"
            }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_path": "track.json",
                "branch_name": "main"
            }))

        result = await self.gitlab.post_learning_track(
            learning_track=self.learning_track)

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "POST")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME,
            "/api/v4/projects/12345/repository/files/track.json"))

        expected = 12345

        self.assertEqual(result, expected)

    async def test_post_learning_track_invalid_image(self):
        """Image is not valid"""

        with self.assertRaisesRegex(
                ValueError, "Invalid image."):

            await self.gitlab.post_learning_track(
                learning_track=self.learning_track_invalid_image)

    async def test_post_learning_track_gitlab_error(
            self, ):
        """Gitlab returns 500 when something goes wrong"""
        self.fake_session.responses.append(
            FakeResponse(status=500)
        )

        with self.assertRaisesRegex(
                gitlab_facade.GitlabError, "Gitlab returned status code 500"):
            await self.gitlab.post_learning_track(self.learning_track)

    async def test_post_learning_track_gitlab_401(self):
        """Gitlab returns 401"""
        self.fake_session.responses.append(
            FakeResponse(status=401)
        )

        with self.assertRaises(gitlab_facade.Unauthorized):
            await self.gitlab.post_learning_track(self.learning_track)

    async def test_post_learning_track_gitlab_400(self):
        """Gitlab returns 400"""
        self.fake_session.responses.append(
            FakeResponse(status=400)
        )

        with self.assertRaises(ValueError):
            await self.gitlab.post_learning_track(self.learning_track)


class GitlabUserProgressTestCase(GitlabMixin, IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.gitlab.access_token = "test_access"

    async def test_get_snippet_id_success(self):
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict=[
                {
                    "id": 1,
                    "title": "User Progress",
                    "description": None,
                    "visibility": "private",
                    "author": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/"
                        "e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
                        "web_url": "http://localhost/root"
                    },
                    "created_at": "2023-07-05T19:41:43.713Z",
                    "updated_at": "2023-07-05T23:29:32.452Z",
                    "project_id": None,
                    "web_url": "http://localhost/-/snippets/51",
                    "raw_url": "http://localhost/-/snippets/51/raw",
                    "ssh_url_to_repo": "git@localhost:snippets/51.git",
                    "http_url_to_repo": "http://localhost/snippets/51.git",
                    "file_name": "progress.json",
                    "files": [
                        {
                            "path": "progress.json",
                            "raw_url": "http://localhost/-/snippets/51/raw/"
                            "main/progress.json"
                        }
                    ]
                },
                {
                    "id": 2,
                    "title": "test snippet 123",
                    "description": None,
                    "visibility": "internal",
                    "author": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/"
                        "e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
                        "web_url": "http://localhost/root"
                    },
                    "created_at": "2023-07-04T17:09:13.175Z",
                    "updated_at": "2023-07-04T17:09:13.371Z",
                    "project_id": None,
                    "web_url": "http://localhost/-/snippets/36",
                    "raw_url": "http://localhost/-/snippets/36/raw",
                    "ssh_url_to_repo": "git@localhost:snippets/36.git",
                    "http_url_to_repo": "http://localhost/snippets/36.git",
                    "file_name": "test.txt",
                    "files": [
                        {
                            "path": "test.txt",
                            "raw_url": "http://localhost/-/snippets/36/raw/"
                            "main/test.txt"
                        }
                    ]
                }]))

        result = await self.gitlab.get_snippet_id()

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "GET")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/snippets/"))

        expected = 1

        self.assertEqual(result, expected)

    async def test_get_snippet_id_not_found(self):
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict=[
                {
                    "id": 1,
                    "title": "Arroz",
                    "description": None,
                    "visibility": "private",
                    "author": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/"
                        "e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
                        "web_url": "http://localhost/root"
                    },
                    "created_at": "2023-07-05T19:41:43.713Z",
                    "updated_at": "2023-07-05T23:29:32.452Z",
                    "project_id": None,
                    "web_url": "http://localhost/-/snippets/51",
                    "raw_url": "http://localhost/-/snippets/51/raw",
                    "ssh_url_to_repo": "git@localhost:snippets/51.git",
                    "http_url_to_repo": "http://localhost/snippets/51.git",
                    "file_name": "progress.json",
                    "files": [
                        {
                            "path": "progress.json",
                            "raw_url": "http://localhost/-/snippets/51/raw/"
                            "main/progress.json"
                        }
                    ]
                },
                {
                    "id": 2,
                    "title": "test snippet 123",
                    "description": None,
                    "visibility": "internal",
                    "author": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/"
                        "e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
                        "web_url": "http://localhost/root"
                    },
                    "created_at": "2023-07-04T17:09:13.175Z",
                    "updated_at": "2023-07-04T17:09:13.371Z",
                    "project_id": None,
                    "web_url": "http://localhost/-/snippets/36",
                    "raw_url": "http://localhost/-/snippets/36/raw",
                    "ssh_url_to_repo": "git@localhost:snippets/36.git",
                    "http_url_to_repo": "http://localhost/snippets/36.git",
                    "file_name": "test.txt",
                    "files": [
                        {
                            "path": "test.txt",
                            "raw_url": "http://localhost/-/snippets/36/raw/"
                            "main/test.txt"
                        }
                    ]
                }]))

        result = await self.gitlab.get_snippet_id()

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "GET")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/snippets/"))

        expected = -1

        self.assertEqual(result, expected)

    async def test_get_snippet_id_error(self):
        self.fake_session.responses.append(
            FakeResponse(status=500, body_dict=[]))

        with self.assertRaises(GitlabError):
            await self.gitlab.get_snippet_id()

    async def test_get_snippet_id_error_404(self):
        self.fake_session.responses.append(
            FakeResponse(status=404, body_dict=[]))

        with self.assertRaises(GitlabError):
            await self.gitlab.get_snippet_id()

    async def test_get_snippet_id_error_401(self):

        self.fake_session.responses.append(
            FakeResponse(status=401, body_dict=[]))

        with self.assertRaises(GitlabError):
            await self.gitlab.get_snippet_id()

    async def test_get_learning_tracks_progress(self):
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict=[
                {
                    "id": 1,
                    "title": "Arroz",
                    "description": None,
                    "visibility": "private",
                    "author": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/"
                        "e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
                        "web_url": "http://localhost/root"
                    },
                    "created_at": "2023-07-05T19:41:43.713Z",
                    "updated_at": "2023-07-05T23:29:32.452Z",
                    "project_id": None,
                    "web_url": "http://localhost/-/snippets/51",
                    "raw_url": "http://localhost/-/snippets/51/raw",
                    "ssh_url_to_repo": "git@localhost:snippets/51.git",
                    "http_url_to_repo": "http://localhost/snippets/51.git",
                    "file_name": "progress.json",
                    "files": [
                        {
                            "path": "progress.json",
                            "raw_url": "http://localhost/-/snippets/51/raw/"
                            "main/progress.json"
                        }
                    ]
                },
                {
                    "id": 2,
                    "title": "test snippet 123",
                    "description": None,
                    "visibility": "internal",
                    "author": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/"
                        "e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
                        "web_url": "http://localhost/root"
                    },
                    "created_at": "2023-07-04T17:09:13.175Z",
                    "updated_at": "2023-07-04T17:09:13.371Z",
                    "project_id": None,
                    "web_url": "http://localhost/-/snippets/36",
                    "raw_url": "http://localhost/-/snippets/36/raw",
                    "ssh_url_to_repo": "git@localhost:snippets/36.git",
                    "http_url_to_repo": "http://localhost/snippets/36.git",
                    "file_name": "test.txt",
                    "files": [
                        {
                            "path": "test.txt",
                            "raw_url": "http://localhost/-/snippets/36/raw/"
                            "main/test.txt"
                        }
                    ]}]))

        await self.gitlab.get_learning_tracks_progress(snippet_id=-2)

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "GET")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/snippets/"))

    async def test_get_learning_tracks_progress_empty(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict=[
                {
                    "id": 1,
                    "title": "Arroz",
                    "description": None,
                    "visibility": "private",
                    "author": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/"
                        "e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
                        "web_url": "http://localhost/root"
                    },
                    "created_at": "2023-07-05T19:41:43.713Z",
                    "updated_at": "2023-07-05T23:29:32.452Z",
                    "project_id": None,
                    "web_url": "http://localhost/-/snippets/51",
                    "raw_url": "http://localhost/-/snippets/51/raw",
                    "ssh_url_to_repo": "git@localhost:snippets/51.git",
                    "http_url_to_repo": "http://localhost/snippets/51.git",
                    "file_name": "progress.json",
                    "files": [
                        {
                            "path": "progress.json",
                            "raw_url": "http://localhost/-/snippets/51/raw/"
                            "main/progress.json"
                        }
                    ]
                },
                {
                    "id": 2,
                    "title": "test snippet 123",
                    "description": None,
                    "visibility": "internal",
                    "author": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/"
                        "e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
                        "web_url": "http://localhost/root"
                    },
                    "created_at": "2023-07-04T17:09:13.175Z",
                    "updated_at": "2023-07-04T17:09:13.371Z",
                    "project_id": None,
                    "web_url": "http://localhost/-/snippets/36",
                    "raw_url": "http://localhost/-/snippets/36/raw",
                    "ssh_url_to_repo": "git@localhost:snippets/36.git",
                    "http_url_to_repo": "http://localhost/snippets/36.git",
                    "file_name": "test.txt",
                    "files": [
                        {
                            "path": "test.txt",
                            "raw_url": "http://localhost/-/snippets/36/"
                            "raw/main/test.txt"
                        }
                    ]}]))

        result = await self.gitlab.get_learning_tracks_progress(snippet_id=-1)

        self.assertEqual(result, [])

    async def test_get_learning_tracks_progress_found(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict="[{\"progress\":"
                         "[{\"resource_id\":"
                         "\"resource_id_1\", \"completed\": false}, {"
                         "\"resource_id\": \"resource_id_2\", \"completed\""
                         ": false}, {\"resource_id\": \"resource_id_3\","
                         "\"completed\": false}], \"learning_track_id\": 216}]"
                         ))

        result = await self.gitlab.get_learning_tracks_progress(snippet_id=3)

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "GET")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/snippets/3/raw"))

        expected = UserProgress(
            learning_track_id=216,
            progress=[
                ResourceProgress(
                    resource_id="resource_id_1",
                    completed=False
                ),
                ResourceProgress(
                    resource_id="resource_id_2",
                    completed=False
                ),
                ResourceProgress(
                    resource_id="resource_id_3",
                    completed=False
                )
            ]
        )

        list_expected = [expected]

        self.assertEqual(result, list_expected)

    async def test_get_learning_track_progress_learning_track_not_found(self):

        # Learning track not found
        self.fake_session.responses.append(
            FakeResponse(status=404, body_dict=[]))

        with self.assertRaisesRegex(
                LookupError, "Learning track not found."):
            await self.gitlab.get_learning_track_progress(88)

    async def test_get_learning_track_progress_found(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict="[{\"progress\":"
                         "[{\"resource_id\":"
                         "\"resource_id_1\", \"completed\": false}, {"
                         "\"resource_id\": \"resource_id_2\", \"completed\""
                         ": false}, {\"resource_id\": \"resource_id_3\","
                         "\"completed\": false}], \"learning_track_id\": 216}]"
                         ))

        result = await self.gitlab.get_learning_track_progress(
            snippet_id=3,
            learning_track_id=216)

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "GET")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/snippets/3/raw"))

        excepted = [
            ResourceProgress(
                resource_id="resource_id_1",
                completed=False
            ),
            ResourceProgress(
                resource_id="resource_id_2",
                completed=False
            ),
            ResourceProgress(
                resource_id="resource_id_3",
                completed=False
            )
        ]

        self.assertEqual(result, excepted)

    async def test_get_learning_track_progress_not_found(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict="[{\"progress\":"
                         "[{\"resource_id\":"
                         "\"resource_id_1\", \"completed\": false}, {"
                         "\"resource_id\": \"resource_id_2\", \"completed\""
                         ": false}, {\"resource_id\": \"resource_id_3\","
                         "\"completed\": false}], \"learning_track_id\": 216}]"
                         ))
        with self.assertRaisesRegex(LookupError, "User progress not found."):
            await self.gitlab.get_learning_track_progress(snippet_id=3,
                                                          learning_track_id=212
                                                          )

    async def test_put_learning_track_progress_not_found(self):
        # Learning track not found
        self.fake_session.responses.append(
            FakeResponse(status=404, body_dict=[]))

        with self.assertRaisesRegex(
                LookupError, "Learning track not found."):
            await self.gitlab.put_learning_track_progress(123, [])

    async def test_put_learning_track_progress_no_file(self):

        # Testing user progress file creation

        # Learning track exists
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        # No snippets found
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict=[]))

        # Snippet creation
        self.fake_session.responses.append(
            FakeResponse(status=201, body_dict={
                "id": 53,
                "title": "bananas",
                "description": None,
                "visibility": "internal",
                "author": {
                    "id": 5,
                    "username": "root1",
                    "name": "maria menl",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "35fd4a5b435460c864a9d6d840dade4a?s=80&d=identicon",
                    "web_url": "http://localhost/root1"
                },
                "created_at": "2023-07-06T10:59:14.476Z",
                "updated_at": "2023-07-06T10:59:14.476Z",
                "project_id": None,
                "web_url": "http://localhost/-/snippets/53",
                "raw_url": "http://localhost/-/snippets/53/raw",
                "ssh_url_to_repo": "git@localhost:snippets/53.git",
                "http_url_to_repo": "http://localhost/snippets/53.git",
                "file_name": "test.txt",
                "files": [
                    {
                        "path": "test.txt",
                        "raw_url": "http://localhost/-/snippets/53/raw/"
                        "main/test.txt"
                    }
                ]
            }))

        progress = UserProgress(
            progress=[
                ResourceProgress(
                    resource_id="resource_id_1",
                    completed=False
                ),
                ResourceProgress(
                    resource_id="resource_id_2",
                    completed=False
                ),
                ResourceProgress(
                    resource_id="resource_id_3",
                    completed=False
                )
            ]
        )

        await self.gitlab.put_learning_track_progress(123, progress)

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "POST")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/snippets"))

    async def test_put_learning_track_progress_new_entry(self):

        # Learning track exists
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        # Snippet found
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict=[
                {
                    "id": 1,
                    "title": "User Progress",
                    "description": None,
                    "visibility": "private",
                    "author": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/"
                        "e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
                        "web_url": "http://localhost/root"
                    },
                    "created_at": "2023-07-05T19:41:43.713Z",
                    "updated_at": "2023-07-05T23:29:32.452Z",
                    "project_id": None,
                    "web_url": "http://localhost/-/snippets/51",
                    "raw_url": "http://localhost/-/snippets/51/raw",
                    "ssh_url_to_repo": "git@localhost:snippets/51.git",
                    "http_url_to_repo": "http://localhost/snippets/51.git",
                    "file_name": "progress.json",
                    "files": [
                        {
                            "path": "progress.json",
                            "raw_url": "http://localhost/-/snippets/51/raw/"
                            "main/progress.json"
                        }
                    ]
                }]))

        # Existing progress
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict="[{\"progress\":"
                         "[{\"resource_id\":"
                         "\"resource_id_1\", \"completed\": false}, {"
                         "\"resource_id\": \"resource_id_2\", \"completed\""
                         ": false}, {\"resource_id\": \"resource_id_3\","
                         "\"completed\": false}], \"learning_track_id\": 216}]"
                         ))

        # Snippet update
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 55,
                "title": "bananas",
                "description": "",
                "visibility": "private",
                "author": {
                    "id": 5,
                    "username": "root1",
                    "name": "maria menl",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "35fd4a5b435460c864a9d6d840dade4a?s=80&d=identicon",
                    "web_url": "http://localhost/root1"
                },
                "created_at": "2023-07-06T12:26:15.677Z",
                "updated_at": "2023-07-06T12:27:12.483Z",
                "project_id": None,
                "web_url": "http://localhost/-/snippets/55",
                "raw_url": "http://localhost/-/snippets/55/raw",
                "ssh_url_to_repo": "git@localhost:snippets/55.git",
                "http_url_to_repo": "http://localhost/snippets/55.git",
                "file_name": "adasdas",
                "files": [
                    {
                        "path": "adasdas",
                        "raw_url": "http://localhost/-/snippets/55/raw/"
                        "main/adasdas"
                    }
                ]
            }))

        progress = UserProgress(
            progress=[
                ResourceProgress(
                    resource_id="resource_id_1",
                    completed=False
                ),
                ResourceProgress(
                    resource_id="resource_id_2",
                    completed=False
                ),
                ResourceProgress(
                    resource_id="resource_id_3",
                    completed=False
                )
            ]
        )

        await self.gitlab.put_learning_track_progress(123, progress)

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "PUT")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/snippets/1"))

    async def test_put_learning_track_progress_update_entry(self):

        # Learning track exists
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        # Snippet found
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict=[
                {
                    "id": 1,
                    "title": "User Progress",
                    "description": None,
                    "visibility": "private",
                    "author": {
                        "id": 1,
                        "username": "root",
                        "name": "Administrator",
                        "state": "active",
                        "avatar_url": "https://www.gravatar.com/avatar/"
                        "e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
                        "web_url": "http://localhost/root"
                    },
                    "created_at": "2023-07-05T19:41:43.713Z",
                    "updated_at": "2023-07-05T23:29:32.452Z",
                    "project_id": None,
                    "web_url": "http://localhost/-/snippets/51",
                    "raw_url": "http://localhost/-/snippets/51/raw",
                    "ssh_url_to_repo": "git@localhost:snippets/51.git",
                    "http_url_to_repo": "http://localhost/snippets/51.git",
                    "file_name": "progress.json",
                    "files": [
                        {
                            "path": "progress.json",
                            "raw_url": "http://localhost/-/snippets/51/raw/"
                            "main/progress.json"
                        }
                    ]
                }]))

        # Existing progress
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict="[{\"progress\":"
                         "[{\"resource_id\":"
                         "\"resource_id_1\", \"completed\": false}, {"
                         "\"resource_id\": \"resource_id_2\", \"completed\""
                         ": false}, {\"resource_id\": \"resource_id_3\","
                         "\"completed\": false}], \"learning_track_id\": 216}]"
                         ))

        # Snippet update
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 55,
                "title": "bananas",
                "description": "",
                "visibility": "private",
                "author": {
                    "id": 5,
                    "username": "root1",
                    "name": "maria menl",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "35fd4a5b435460c864a9d6d840dade4a?s=80&d=identicon",
                    "web_url": "http://localhost/root1"
                },
                "created_at": "2023-07-06T12:26:15.677Z",
                "updated_at": "2023-07-06T12:27:12.483Z",
                "project_id": None,
                "web_url": "http://localhost/-/snippets/55",
                "raw_url": "http://localhost/-/snippets/55/raw",
                "ssh_url_to_repo": "git@localhost:snippets/55.git",
                "http_url_to_repo": "http://localhost/snippets/55.git",
                "file_name": "adasdas",
                "files": [
                    {
                        "path": "adasdas",
                        "raw_url": "http://localhost/-/snippets/55/raw/"
                        "main/adasdas"
                    }
                ]
            }))

        progress = UserProgress(
            progress=[
                ResourceProgress(
                    resource_id="resource_id_1",
                    completed=False
                ),
                ResourceProgress(
                    resource_id="resource_id_2",
                    completed=False
                ),
                ResourceProgress(
                    resource_id="resource_id_3",
                    completed=False
                )
            ]
        )

        await self.gitlab.put_learning_track_progress(216, progress)

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "PUT")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/snippets/1"))

    async def test_get_learning_track_commits_not_found(self):
        # Learning track not found
        self.fake_session.responses.append(
            FakeResponse(status=404, body_dict=[])
        )

        with self.assertRaises(
                gitlab_facade.GitlabLookupError):
            await self.gitlab.get_learning_track_commits(99)

    async def test_get_learning_track_commits_sucess(self):
        # Learning track commits
        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict=[{
                'id': '9e023e77f0f7b53c17419358aadfcb787921404d',
                'short_id': '9e023e77',
                'created_at': '2023-07-09T14:25:58.000+00:00',
                'parent_ids': [],
                'title': 'Create learning track',
                'message': '{"description": "string1", "career": "string2"}',
                'author_name': 'antonio antonio',
                'author_email': 'admin@example.com',
                'authored_date': '2023-07-09T14:25:58.000+00:00',
                'committer_name': 'Administrator',
                'committer_email': 'admin@example.com',
                'committed_date': '2023-07-09T14:25:58.000+00:00',
                'trailers': {},
                'web_url': "http://gitlab.example.com/root/1234567891-2a31b4/"
                "-/commit/9e023e77f0f7b53c17419358aadfcb787921404d"
            }]
            )
        )

        result = await self.gitlab.get_learning_track_commits(12345)

        request = self.fake_session.requests.pop()
        self.assertEqual(request.method, "GET")
        self.assertEqual(
            request.url,
            urljoin(
                TEST_HOSTNAME,
                "/api/v4/projects/12345/repository/commits?path=track.json"
            )
        )

        excepted = [
            LearningTrackCommit(
                change_id='9e023e77f0f7b53c17419358aadfcb787921404d',
                short_id='9e023e77',
                created_at='2023-07-09T14:25:58.000+00:00',
                parent_ids=[],
                title='Create learning track',
                change_message=dumps(
                    {"description": "string1", "career": "string2"}
                ),
                author_name='antonio antonio',
                author_email='admin@example.com',
                authored_date='2023-07-09T14:25:58.000+00:00',
                committer_name='Administrator',
                committer_email='admin@example.com',
                change_date='2023-07-09T14:25:58.000+00:00',
                trailers={},
                web_url="http://gitlab.example.com/root/1234567891-2a31b4/"
                "-/commit/9e023e77f0f7b53c17419358aadfcb787921404d"
            ),
        ]

        self.assertEqual(result, excepted)

    async def test_get_learning_track_commit_id_not_found(self):
        self.fake_session.responses.append(
            FakeResponse(
                status=404,
                body_dict={"message": "404 Commit Not Found"}
            )
        )

        with self.assertRaises(
                gitlab_facade.GitlabLookupError):
            await self.gitlab.get_learning_track(999, change_id="abc")


class GitlabCopyLearningTrackTestCase(GitlabMixin, IsolatedAsyncioTestCase):

    async def test_copy_learning_track_404(self):
        """Gitlab returns 404"""
        self.fake_session.responses.append(
            FakeResponse(status=404)
        )

        with self.assertRaisesRegex(expected_exception=LookupError,
                                    expected_regex="123456"):
            await self.gitlab.copy_learning_track("123456")

    async def test_copy_learning_track_success(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        self.fake_session.responses.append(
            FakeResponse(status=201, body_dict={
                "id": 123456,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        # Suggestions deleted successfully
        self.fake_session.responses.append(
            FakeResponse(status=204, body_dict={}))

        result = await self.gitlab.copy_learning_track("12345")

        copy_request = self.fake_session.requests[1]
        delete_request = self.fake_session.requests[2]

        self.assertEqual(copy_request.method, "POST")
        self.assertEqual(delete_request.method, "DELETE")

        self.assertEqual(copy_request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/projects/12345/fork"))

        self.assertEqual(delete_request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/projects/123456/repository/"
            "files/suggestions.json"))

        self.assertEqual(result, 123456)

    async def test_copy_learning_track_success_no_suggestions(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        self.fake_session.responses.append(
            FakeResponse(status=201, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        # Suggestions deleted successfully
        self.fake_session.responses.append(
            FakeResponse(status=204, body_dict={}))

        result = await self.gitlab.copy_learning_track("1234")

        self.assertEqual(result, 12345)


class GitlabRevertLearningTrackTestCase(GitlabMixin, IsolatedAsyncioTestCase):

    async def test_revert_learning_track_success(self):
        """Gitlab returns 201"""

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        self.fake_session.responses.append(
            FakeResponse(status=201, body_dict={
                "id": 12345,
                "repository_access_level": "enabled",
                "visibility": "private",
                "owner": {
                    "id": 15,
                    "username": "antonio",
                    "name": "antonio antonio",
                    "state": "active",
                    "avatar_url": "https://www.gravatar.com/avatar/"
                    "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                    "web_url": "http://gitlab.example.com/antonio"
                },
                "description": "{\"description\": \"string1\", \"career\"" +
                ": \"string2\"}",
                "name": "str1 123456",
                "tag_list": [
                    "string"
                ],
                "topics": [
                    "string"
                ],
                "avatar_url": None
            }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_path": "track.json",
                "branch_name": "main"
            }))

        result = await self.gitlab.revert_learning_track(
            12345, "df9f6c4b5c5eb1f462daca015410f9cb34a2e6f0")

        get_request = self.fake_session.requests[0]
        put_request = self.fake_session.requests[1]

        self.assertEqual(get_request.method, "GET")
        self.assertEqual(put_request.method, "PUT")

        self.assertEqual(get_request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/projects/12345/repository/files/"
            "track.json/raw?ref=df9f6c4b5c5eb1f462daca015410f9cb34a2e6f0"))

        self.assertEqual(put_request.url, urljoin(
            TEST_HOSTNAME,
            "/api/v4/projects/12345/repository/files/track.json"))

        self.assertEqual(result, None)

    async def test_revert_learning_track_404(self):
        """
        404 Commit Not Found
        404 File Not Found
        404 Project Not Found
        """

        self.fake_session.responses.append(
            FakeResponse(status=404, body_dict={
                "message": "404 Project Not Found"
            }))

        with self.assertRaisesRegex(
                LookupError, "123"):
            await self.gitlab.revert_learning_track(
                123, "df9f6c4b5c5eb1f462daca015410f9cb34a2e6f0")

        self.fake_session.responses.append(
            FakeResponse(status=404, body_dict={
                "message": "404 File Not Found"
            }))

        with self.assertRaisesRegex(
                LookupError, "track.json"):
            await self.gitlab.revert_learning_track(
                12345, "df9f6c4b5c5eb1f462daca015410f9cb34a2e6f0")

        self.fake_session.responses.append(
            FakeResponse(status=404, body_dict={
                "message": "404 Commit Not Found"
            }))

        with self.assertRaisesRegex(
                LookupError, "df9f6c4b5c5eb1f462daca015"):
            await self.gitlab.revert_learning_track(
                12345, "df9f6c4b5c5eb1f462daca015")

    async def test_revert_learning_track_Error(self):
        """Gitlab returns Error"""

        self.fake_session.responses.append(
            FakeResponse(status=400, body_dict={
                "message": "Error reverting the learning track."
            }))

        with self.assertRaisesRegex(
                GitlabError, "Error reverting the learning track."):
            await self.gitlab.revert_learning_track(
                12345, "df9f6c4b5c5eb1f462daca015410f9cb34a2e6f0")


class GitlabRootLongTermTestCase(GitlabMixin, IsolatedAsyncioTestCase):

    async def test_get_root_long_term_token(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 32,
                "name": "main",
                "revoked": False,
                "created_at": "2023-07-11T20:28:09.757Z",
                "scopes": [
                        "api",
                        "read_user",
                        "sudo",
                        "read_api",
                        "read_repository",
                        "write_repository",
                        "admin_mode",
                        "admin_mode"
                ],
                "user_id": 1,
                "last_used_at": None,
                "active": None,
                "expires_at": None,
                "token": "glpat-LZ3Hf-etrUcezUT3fsSk"
            }))

        result = await self.gitlab.get_root_long_term_token("1")

        self.assertEqual(result, "glpat-LZ3Hf-etrUcezUT3fsSk")

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "POST")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/users/1/personal_access_tokens"))


class GitlabSuggestionsTestCase(GitlabMixin, IsolatedAsyncioTestCase):

    async def test_get_suggestions_success(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_name": "suggestions.json",
                "file_path": "suggestions.json",
                "size": 915,
                "encoding": "base64",
                "content_sha256": "a9016392b8b96e36cf120c945a3d31ae1258147a59f"
                "8d602e4b0ccbaaab6011e",
                "ref": "main",
                "blob_id": "05f7eb136c41ac663a71d039f411be91f71f9f91",
                "commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "last_commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "execute_filemode": False,
                "content": "WwogIHsKICAgICJzdWdnZXN0aW9uX2lkIjogInN0cmluZyIsCi"
                "AgICAic3VnZ2VzdGlvbl9zdGF0dXMiOiAicmVqZWN0ZWQiLAogICAgImxlc3N"
                "vbnMiOiBbCiAgICAgIHsKICAgICAgICAibGVzc29uX2lkIjogInN0cmluZyIs"
                "CiAgICAgICAgIm5hbWUiOiAic3RyaW5nIiwKICAgICAgICAicmVzb3VyY2VzI"
                "jogWwogICAgICAgICAgewogICAgICAgICAgICAicmVzb3VyY2VfaWQiOiAic3"
                "RyaW5nIiwKICAgICAgICAgICAgImxpbmsiOiAic3RyaW5nIiwKICAgICAgICA"
                "gICAgInRpdGxlIjogInN0cmluZyIsCiAgICAgICAgICAgICJzb3VyY2UiOiAi"
                "c3RyaW5nIiwKICAgICAgICAgICAgInJlc291cmNlX3R5cGUiOiAiYm9vayIsC"
                "iAgICAgICAgICAgICJkdXJhdGlvbiI6IDAsCiAgICAgICAgICAgICJhZGRlZE"
                "J5IjogInN0cmluZyIKICAgICAgICAgIH0KICAgICAgICBdCiAgICAgIH0KICA"
                "gIF0KICB9LAogIHsKICAgICJzdWdnZXN0aW9uX2lkIjogInN0cmluZzEiLAog"
                "ICAgInN1Z2dlc3Rpb25fc3RhdHVzIjogIm9wZW4iLAogICAgImxlc3NvbnMiO"
                "iBbCiAgICAgIHsKICAgICAgICAibGVzc29uX2lkIjogInN0cmluZyIsCiAgIC"
                "AgICAgIm5hbWUiOiAic3RyaW5nIiwKICAgICAgICAicmVzb3VyY2VzIjogWwo"
                "gICAgICAgICAgewogICAgICAgICAgICAicmVzb3VyY2VfaWQiOiAic3RyaW5n"
                "IiwKICAgICAgICAgICAgImxpbmsiOiAic3RyaW5nIiwKICAgICAgICAgICAgI"
                "nRpdGxlIjogInN0cmluZyIsCiAgICAgICAgICAgICJzb3VyY2UiOiAic3RyaW"
                "5nIiwKICAgICAgICAgICAgInJlc291cmNlX3R5cGUiOiAiYm9vayIsCiAgICA"
                "gICAgICAgICJkdXJhdGlvbiI6IDAsCiAgICAgICAgICAgICJhZGRlZEJ5Ijog"
                "InN0cmluZyIKICAgICAgICAgIH0KICAgICAgICBdCiAgICAgIH0KICAgIF0KI"
                "CB9Cl0="
                }))

        result = await self.gitlab.get_suggestions("1")

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "GET")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/projects/1/repository/files/"
            "suggestions.json/?ref=main"))

        expected = [
            {
                "suggestion_id": "string",
                "suggestion_status": "rejected",
                "lessons": [
                    {
                        "lesson_id": "string",
                        "name": "string",
                        "resources": [
                            {
                                "resource_id": "string",
                                "link": "string",
                                "title": "string",
                                "source": "string",
                                "resource_type": "book",
                                "duration": 0,
                                "addedBy": "string"
                            }
                        ]
                    }
                ]
            },
            {
                "suggestion_id": "string1",
                "suggestion_status": "open",
                "lessons": [
                    {
                        "lesson_id": "string",
                        "name": "string",
                        "resources": [
                            {
                                "resource_id": "string",
                                "link": "string",
                                "title": "string",
                                "source": "string",
                                "resource_type": "book",
                                "duration": 0,
                                "addedBy": "string"
                            }
                        ]
                    }
                    ]
            }
            ]

        self.assertEqual(result, expected)

    async def test_get_open_suggestions(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_name": "suggestions.json",
                "file_path": "suggestions.json",
                "size": 915,
                "encoding": "base64",
                "content_sha256": "a9016392b8b96e36cf120c945a3d31ae1258147a59f"
                "8d602e4b0ccbaaab6011e",
                "ref": "main",
                "blob_id": "05f7eb136c41ac663a71d039f411be91f71f9f91",
                "commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "last_commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "execute_filemode": False,
                "content": "WwogIHsKICAgICJzdWdnZXN0aW9uX2lkIjogInN0cmluZyIsCi"
                "AgICAic3VnZ2VzdGlvbl9zdGF0dXMiOiAicmVqZWN0ZWQiLAogICAgImxlc3N"
                "vbnMiOiBbCiAgICAgIHsKICAgICAgICAibGVzc29uX2lkIjogInN0cmluZyIs"
                "CiAgICAgICAgIm5hbWUiOiAic3RyaW5nIiwKICAgICAgICAicmVzb3VyY2VzI"
                "jogWwogICAgICAgICAgewogICAgICAgICAgICAicmVzb3VyY2VfaWQiOiAic3"
                "RyaW5nIiwKICAgICAgICAgICAgImxpbmsiOiAic3RyaW5nIiwKICAgICAgICA"
                "gICAgInRpdGxlIjogInN0cmluZyIsCiAgICAgICAgICAgICJzb3VyY2UiOiAi"
                "c3RyaW5nIiwKICAgICAgICAgICAgInJlc291cmNlX3R5cGUiOiAiYm9vayIsC"
                "iAgICAgICAgICAgICJkdXJhdGlvbiI6IDAsCiAgICAgICAgICAgICJhZGRlZE"
                "J5IjogInN0cmluZyIKICAgICAgICAgIH0KICAgICAgICBdCiAgICAgIH0KICA"
                "gIF0KICB9LAogIHsKICAgICJzdWdnZXN0aW9uX2lkIjogInN0cmluZzEiLAog"
                "ICAgInN1Z2dlc3Rpb25fc3RhdHVzIjogIm9wZW4iLAogICAgImxlc3NvbnMiO"
                "iBbCiAgICAgIHsKICAgICAgICAibGVzc29uX2lkIjogInN0cmluZyIsCiAgIC"
                "AgICAgIm5hbWUiOiAic3RyaW5nIiwKICAgICAgICAicmVzb3VyY2VzIjogWwo"
                "gICAgICAgICAgewogICAgICAgICAgICAicmVzb3VyY2VfaWQiOiAic3RyaW5n"
                "IiwKICAgICAgICAgICAgImxpbmsiOiAic3RyaW5nIiwKICAgICAgICAgICAgI"
                "nRpdGxlIjogInN0cmluZyIsCiAgICAgICAgICAgICJzb3VyY2UiOiAic3RyaW"
                "5nIiwKICAgICAgICAgICAgInJlc291cmNlX3R5cGUiOiAiYm9vayIsCiAgICA"
                "gICAgICAgICJkdXJhdGlvbiI6IDAsCiAgICAgICAgICAgICJhZGRlZEJ5Ijog"
                "InN0cmluZyIKICAgICAgICAgIH0KICAgICAgICBdCiAgICAgIH0KICAgIF0KI"
                "CB9Cl0="
                }))

        result = await self.gitlab.get_open_suggestions("1")

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "GET")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/projects/1/repository/files/"
            "suggestions.json/?ref=main"))

        expected = [
            {
                "suggestion_id": "string1",
                "suggestion_status": "open",
                "lessons": [
                    {
                        "lesson_id": "string",
                        "name": "string",
                        "resources": [
                            {
                                "resource_id": "string",
                                "link": "string",
                                "title": "string",
                                "source": "string",
                                "resource_type": "book",
                                "duration": 0,
                                "addedBy": "string"
                            }
                        ]
                    }
                    ]
            }
            ]

        self.assertEqual(result, expected)

    async def test_get_suggestions_learning_track_not_found(self):

        self.fake_session.responses.append(
            FakeResponse(status=404, body_dict={
                "message": "404 Project Not Found"
                }))

        with self.assertRaisesRegex(LookupError, "1"):
            await self.gitlab.get_suggestions("1")

    async def test_get_suggestions_no_suggestions(self):

        self.fake_session.responses.append(
            FakeResponse(status=404, body_dict={
                "message": "404 File Not Found"
                }))

        result = await self.gitlab.get_suggestions("1")

        self.assertEqual(result, [])

    async def test_post_suggestions_sucess(self):
        self.fake_session.responses.append(
            FakeResponse(status=404, body_dict={
                "message": "404 File Not Found"
                }))

        self.fake_session.responses.append(
            FakeResponse(status=201, body_dict={
                "file_path": "suggestions.json",
                "branch": "main"
                }))

        suggestion = gitlab_facade.LearningTrackSuggestion(
            lesson_id="string1",
            name="string",
            description="dadxadxas",
            resource=gitlab_facade.Resource(
                resource_id="string",
                link="string",
                title="string",
                source="string",
                resource_type="book",
                duration=0,
                addedBy="string"))

        await self.gitlab.post_suggestions(123, [suggestion])

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "POST")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME, "/api/v4/projects/123/repository/files/"
            "suggestions.json"))

    async def test_post_suggestions_failure(self):

        self.fake_session.responses.append(
            FakeResponse(status=404, body_dict={
                "message": "404 File Not Found"
                }))

        self.fake_session.responses.append(
            FakeResponse(status=500))

        suggestion = gitlab_facade.LearningTrackSuggestion(
                    lesson_id="string1",
                    name="string",
                    description="dadxadxas",
                    resource=gitlab_facade.Resource(
                        resource_id="string",
                        link="string",
                        title="string",
                        source="string",
                        resource_type="book",
                        duration=0,
                        addedBy="string"))

        with self.assertRaisesRegex(GitlabError,
                                    "Gitlab returned status code 500"):
            await self.gitlab.post_suggestions(123, [suggestion])

    async def test_manage_suggestion_not_found(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_name": "suggestions.json",
                "file_path": "suggestions.json",
                "size": 915,
                "encoding": "base64",
                "content_sha256": "a9016392b8b96e36cf120c945a3d31ae1258147a59f"
                "8d602e4b0ccbaaab6011e",
                "ref": "main",
                "blob_id": "05f7eb136c41ac663a71d039f411be91f71f9f91",
                "commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "last_commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "execute_filemode": False,
                "content": "WwogICAgewogICAgICAgICJzdWdnZXN0aW9uX2lkIjogInN0cm"
                "luZyIsCiAgICAgICAgImxlc3Nvbl9pZCI6ICJzdHJpbmciLAogICAgICAgICJ"
                "uYW1lIjogInN0cmluZyIsCiAgICAgICAgImRlc2NyaXB0aW9uIjogInN0cmlu"
                "ZyIsCiAgICAgICAgInN1Z2dlc3Rpb25fc3RhdHVzIjogIm9wZW4iLAogICAgI"
                "CAgICJyZXNvdXJjZSI6IHsKICAgICAgICAgICAgInJlc291cmNlX2lkIjogIn"
                "N0cmluZyIsCiAgICAgICAgICAgICJsaW5rIjogInN0cmluZyIsCiAgICAgICA"
                "gICAgICJ0aXRsZSI6ICJzdHJpbmciLAogICAgICAgICAgICAic291cmNlIjog"
                "InN0cmluZyIsCiAgICAgICAgICAgICJyZXNvdXJjZV90eXBlIjogImJvb2siL"
                "AogICAgICAgICAgICAiZHVyYXRpb24iOiAwLAogICAgICAgICAgICAiYWRkZW"
                "RCeSI6ICJzdHJpbmciCiAgICAgICAgfQogICAgfSwKICAgIHsKICAgICAgICA"
                "ic3VnZ2VzdGlvbl9pZCI6ICJzdHJpbmcxIiwKICAgICAgICAibGVzc29uX2lk"
                "IjogInN0cmluZzEiLAogICAgICAgICJuYW1lIjogInN0cmluZyIsCiAgICAgI"
                "CAgImRlc2NyaXB0aW9uIjogInN0cmluZyIsCiAgICAgICAgInN1Z2dlc3Rpb2"
                "5fc3RhdHVzIjogInJlamVjdCIsCiAgICAgICAgInJlc291cmNlIjogewogICA"
                "gICAgICAgICAicmVzb3VyY2VfaWQiOiAic3RyaW5nMSIsCiAgICAgICAgICAg"
                "ICJsaW5rIjogInN0cmluZyIsCiAgICAgICAgICAgICJ0aXRsZSI6ICJzdHJpb"
                "mciLAogICAgICAgICAgICAic291cmNlIjogInN0cmluZyIsCiAgICAgICAgIC"
                "AgICJyZXNvdXJjZV90eXBlIjogImJvb2siLAogICAgICAgICAgICAiZHVyYXR"
                "pb24iOiAwLAogICAgICAgICAgICAiYWRkZWRCeSI6ICJzdHJpbmciCiAgICAg"
                "ICAgfQogICAgfQpdCg=="
                }))

        with self.assertRaisesRegex(LookupError,
                                    "Suggestion not found"):
            await self.gitlab.manage_suggestion(123, "addsa", "accept")

    async def test_manage_suggestion_success_reject(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_name": "suggestions.json",
                "file_path": "suggestions.json",
                "size": 915,
                "encoding": "base64",
                "content_sha256": "a9016392b8b96e36cf120c945a3d31ae1258147a59f"
                "8d602e4b0ccbaaab6011e",
                "ref": "main",
                "blob_id": "05f7eb136c41ac663a71d039f411be91f71f9f91",
                "commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "last_commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "execute_filemode": False,
                "content": "WwogICAgewogICAgICAgICJzdWdnZXN0aW9uX2lkIjogInN0cm"
                "luZyIsCiAgICAgICAgImxlc3Nvbl9pZCI6ICJzdHJpbmciLAogICAgICAgICJ"
                "uYW1lIjogInN0cmluZyIsCiAgICAgICAgImRlc2NyaXB0aW9uIjogInN0cmlu"
                "ZyIsCiAgICAgICAgInN1Z2dlc3Rpb25fc3RhdHVzIjogIm9wZW4iLAogICAgI"
                "CAgICJyZXNvdXJjZSI6IHsKICAgICAgICAgICAgInJlc291cmNlX2lkIjogIn"
                "N0cmluZyIsCiAgICAgICAgICAgICJsaW5rIjogInN0cmluZyIsCiAgICAgICA"
                "gICAgICJ0aXRsZSI6ICJzdHJpbmciLAogICAgICAgICAgICAic291cmNlIjog"
                "InN0cmluZyIsCiAgICAgICAgICAgICJyZXNvdXJjZV90eXBlIjogImJvb2siL"
                "AogICAgICAgICAgICAiZHVyYXRpb24iOiAwLAogICAgICAgICAgICAiYWRkZW"
                "RCeSI6ICJzdHJpbmciCiAgICAgICAgfQogICAgfSwKICAgIHsKICAgICAgICA"
                "ic3VnZ2VzdGlvbl9pZCI6ICJzdHJpbmcxIiwKICAgICAgICAibGVzc29uX2lk"
                "IjogInN0cmluZzEiLAogICAgICAgICJuYW1lIjogInN0cmluZyIsCiAgICAgI"
                "CAgImRlc2NyaXB0aW9uIjogInN0cmluZyIsCiAgICAgICAgInN1Z2dlc3Rpb2"
                "5fc3RhdHVzIjogInJlamVjdCIsCiAgICAgICAgInJlc291cmNlIjogewogICA"
                "gICAgICAgICAicmVzb3VyY2VfaWQiOiAic3RyaW5nMSIsCiAgICAgICAgICAg"
                "ICJsaW5rIjogInN0cmluZyIsCiAgICAgICAgICAgICJ0aXRsZSI6ICJzdHJpb"
                "mciLAogICAgICAgICAgICAic291cmNlIjogInN0cmluZyIsCiAgICAgICAgIC"
                "AgICJyZXNvdXJjZV90eXBlIjogImJvb2siLAogICAgICAgICAgICAiZHVyYXR"
                "pb24iOiAwLAogICAgICAgICAgICAiYWRkZWRCeSI6ICJzdHJpbmciCiAgICAg"
                "ICAgfQogICAgfQpdCg=="
                }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": "31b12e5abe6e4526d7993018ded7f7b56106c6fd",
                "short_id": "31b12e5a",
                "created_at": "2023-07-14T19:50:02.000+00:00",
                "parent_ids": [
                    "46fb6de6f6097537e3a3131f3f3513cb1ae76727"
                ],
                "title": "batatas",
                "message": "batatas",
                "author_name": "Administrator",
                "author_email": "admin@example.com",
                "authored_date": "2023-07-14T19:50:02.000+00:00",
                "committer_name": "Administrator",
                "committer_email": "admin@example.com",
                "committed_date": "2023-07-14T19:50:02.000+00:00",
                "trailers": {},
                "web_url": "http://gitlab/root/1234567891-119d1a/-/commit/"
                "31b12e5abe6e4526d7993018ded7f7b56106c6fd",
                "stats": {
                    "additions": 1,
                    "deletions": 1,
                    "total": 2
                },
                "status": None,
                "project_id": 280,
                "last_pipeline": None
            }))

        await self.gitlab.manage_suggestion(123, "string", "reject")

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "POST")

        self.assertEqual(request.url, urljoin(TEST_HOSTNAME,
                                              "api/v4/projects/123/repository"
                                              "/commits"))
        raw_request_data = json.loads(request.data)

        self.assertEqual(raw_request_data["branch"], "main")
        self.assertEqual(raw_request_data["commit_message"], "Add resource"
                         " string to lesson string")
        self.assertEqual(len(raw_request_data["actions"]), 1)
        self.assertEqual(raw_request_data["actions"][0]["action"], "update")
        self.assertEqual(raw_request_data["actions"][0]["file_path"],
                         "suggestions.json")

    async def test_manage_suggestion_suggestion_not_open(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_name": "suggestions.json",
                "file_path": "suggestions.json",
                "size": 915,
                "encoding": "base64",
                "content_sha256": "a9016392b8b96e36cf120c945a3d31ae1258147a59f"
                "8d602e4b0ccbaaab6011e",
                "ref": "main",
                "blob_id": "05f7eb136c41ac663a71d039f411be91f71f9f91",
                "commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "last_commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "execute_filemode": False,
                "content": "WwogICAgewogICAgICAgICJzdWdnZXN0aW9uX2lkIjogInN0cm"
                "luZyIsCiAgICAgICAgImxlc3Nvbl9pZCI6ICJzdHJpbmciLAogICAgICAgICJ"
                "uYW1lIjogInN0cmluZyIsCiAgICAgICAgImRlc2NyaXB0aW9uIjogInN0cmlu"
                "ZyIsCiAgICAgICAgInN1Z2dlc3Rpb25fc3RhdHVzIjogIm9wZW4iLAogICAgI"
                "CAgICJyZXNvdXJjZSI6IHsKICAgICAgICAgICAgInJlc291cmNlX2lkIjogIn"
                "N0cmluZyIsCiAgICAgICAgICAgICJsaW5rIjogInN0cmluZyIsCiAgICAgICA"
                "gICAgICJ0aXRsZSI6ICJzdHJpbmciLAogICAgICAgICAgICAic291cmNlIjog"
                "InN0cmluZyIsCiAgICAgICAgICAgICJyZXNvdXJjZV90eXBlIjogImJvb2siL"
                "AogICAgICAgICAgICAiZHVyYXRpb24iOiAwLAogICAgICAgICAgICAiYWRkZW"
                "RCeSI6ICJzdHJpbmciCiAgICAgICAgfQogICAgfSwKICAgIHsKICAgICAgICA"
                "ic3VnZ2VzdGlvbl9pZCI6ICJzdHJpbmcxIiwKICAgICAgICAibGVzc29uX2lk"
                "IjogInN0cmluZzEiLAogICAgICAgICJuYW1lIjogInN0cmluZyIsCiAgICAgI"
                "CAgImRlc2NyaXB0aW9uIjogInN0cmluZyIsCiAgICAgICAgInN1Z2dlc3Rpb2"
                "5fc3RhdHVzIjogInJlamVjdCIsCiAgICAgICAgInJlc291cmNlIjogewogICA"
                "gICAgICAgICAicmVzb3VyY2VfaWQiOiAic3RyaW5nMSIsCiAgICAgICAgICAg"
                "ICJsaW5rIjogInN0cmluZyIsCiAgICAgICAgICAgICJ0aXRsZSI6ICJzdHJpb"
                "mciLAogICAgICAgICAgICAic291cmNlIjogInN0cmluZyIsCiAgICAgICAgIC"
                "AgICJyZXNvdXJjZV90eXBlIjogImJvb2siLAogICAgICAgICAgICAiZHVyYXR"
                "pb24iOiAwLAogICAgICAgICAgICAiYWRkZWRCeSI6ICJzdHJpbmciCiAgICAg"
                "ICAgfQogICAgfQpdCg=="
                }))

        with self.assertRaisesRegex(LookupError,
                                    "Suggestion already managed."):
            await self.gitlab.manage_suggestion(123, "string1", "accept")

    async def test_manage_suggestion_success_approve(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_name": "suggestions.json",
                "file_path": "suggestions.json",
                "size": 915,
                "encoding": "base64",
                "content_sha256": "a9016392b8b96e36cf120c945a3d31ae1258147a59f"
                "8d602e4b0ccbaaab6011e",
                "ref": "main",
                "blob_id": "05f7eb136c41ac663a71d039f411be91f71f9f91",
                "commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "last_commit_id": "be80fabd2487ab43b4431ca8dd413310e0879b22",
                "execute_filemode": False,
                "content": "WwogICAgewogICAgICAgICJzdWdnZXN0aW9uX2lkIjogInN0cm"
                "luZyIsCiAgICAgICAgImxlc3Nvbl9pZCI6ICJzb21lVVVJRCIsCiAgICAgICA"
                "gIm5hbWUiOiAic3RyaW5nIiwKICAgICAgICAiZGVzY3JpcHRpb24iOiAic3Ry"
                "aW5nIiwKICAgICAgICAic3VnZ2VzdGlvbl9zdGF0dXMiOiAib3BlbiIsCiAgI"
                "CAgICAgInJlc291cmNlIjogewogICAgICAgICAgICAicmVzb3VyY2VfaWQiOi"
                "Aic3RyaW5nIiwKICAgICAgICAgICAgImxpbmsiOiAic3RyaW5nIiwKICAgICA"
                "gICAgICAgInRpdGxlIjogInN0cmluZyIsCiAgICAgICAgICAgICJzb3VyY2Ui"
                "OiAic3RyaW5nIiwKICAgICAgICAgICAgInJlc291cmNlX3R5cGUiOiAiYm9va"
                "yIsCiAgICAgICAgICAgICJkdXJhdGlvbiI6IDAsCiAgICAgICAgICAgICJhZG"
                "RlZEJ5IjogInN0cmluZyIKICAgICAgICB9CiAgICB9LAogICAgewogICAgICA"
                "gICJzdWdnZXN0aW9uX2lkIjogInN0cmluZzEiLAogICAgICAgICJsZXNzb25f"
                "aWQiOiAic3RyaW5nMSIsCiAgICAgICAgIm5hbWUiOiAic3RyaW5nIiwKICAgI"
                "CAgICAiZGVzY3JpcHRpb24iOiAic3RyaW5nIiwKICAgICAgICAic3VnZ2VzdG"
                "lvbl9zdGF0dXMiOiAicmVqZWN0IiwKICAgICAgICAicmVzb3VyY2UiOiB7CiA"
                "gICAgICAgICAgICJyZXNvdXJjZV9pZCI6ICJzdHJpbmcxIiwKICAgICAgICAg"
                "ICAgImxpbmsiOiAic3RyaW5nIiwKICAgICAgICAgICAgInRpdGxlIjogInN0c"
                "mluZyIsCiAgICAgICAgICAgICJzb3VyY2UiOiAic3RyaW5nIiwKICAgICAgIC"
                "AgICAgInJlc291cmNlX3R5cGUiOiAiYm9vayIsCiAgICAgICAgICAgICJkdXJ"
                "hdGlvbiI6IDAsCiAgICAgICAgICAgICJhZGRlZEJ5IjogInN0cmluZyIKICAg"
                "ICAgICB9CiAgICB9Cl0K"
                }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_name": "track.json",
                "file_path": "track.json",
                "size": 2121,
                "encoding": "base64",
                "content_sha256": "d142e040117e680aafe515a53a33f4baeb49fc38953"
                "5edeb91869a917b173571",
                "ref": "main",
                "blob_id": "f5443b5921eb1b4fa4367eaffa17532b213d47b2",
                "commit_id": "d6fa002403c8515afe0d0f215cfdf7f2631ef518",
                "last_commit_id": "d6fa002403c8515afe0d0f215cfdf7f2631ef518",
                "execute_filemode": "false",
                "content": "ewoJImNhcmVlcl9wYXRoIjogInNvbWVDYXJlZXJQYXRoIiw"
                "KCSJsZXZlbCI6ICJleHBlcnQiLAoJInNraWxscyI6ICJza2lsbHMiL"
                "AoJImxlc3NvbnMiOiBbewoJCSJsZXNzb25faWQiOiAic29tZVVVSUQ"
                "iLAoJCSJuYW1lIjogInNvbWVOYW1lIiwKCQkicmVzb3VyY2VzIjogW3"
                "sKCQkJCSJsaW5rIjogImh0dHA6Ly8uc29tZWxpbmsuY29tIiwKCQkJC"
                "SJyZXNvdXJjZV9pZCI6ICJzb21lVVVJRCIsCgkJCQkidGl0bGUiOiAi"
                "c29tZVRpdGxlIiwKCQkJCSJzb3VyY2UiOiAic29tZVRpdGxlIiwKCQkJ"
                "CSJyZXNvdXJjZV90eXBlIjogImJvb2siLAoJCQkJImR1cmF0aW9uIjog"
                "MTAsCgkJCQkiYWRkZWRCeSI6ICJxdWltYmFycmVpcm9zIgoJCQl9LAoJ"
                "CQl7CgkJCQkibGluayI6ICJodHRwOi8vLnNvbWVsaW5rLmNvbSIsCgkJ"
                "CQkicmVzb3VyY2VfaWQiOiAic29tZVVVSUQiLAoJCQkJInRpdGxlIjog"
                "InNvbWVUaXRsZSIsCgkJCQkic291cmNlIjogInNvbWVUaXRsZSIsCgkJ"
                "CQkicmVzb3VyY2VfdHlwZSI6ICJib29rIiwKCQkJCSJkdXJhdGlvbiI6"
                "IDEwLAoJCQkJImFkZGVkQnkiOiAicXVpbWJhcnJlaXJvcyIKCQkJfQoJ"
                "CV0KCgl9XQp9"
            }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": "31b12e5abe6e4526d7993018ded7f7b56106c6fd",
                "short_id": "31b12e5a",
                "created_at": "2023-07-14T19:50:02.000+00:00",
                "parent_ids": [
                    "46fb6de6f6097537e3a3131f3f3513cb1ae76727"
                ],
                "title": "batatas",
                "message": "batatas",
                "author_name": "Administrator",
                "author_email": "admin@example.com",
                "authored_date": "2023-07-14T19:50:02.000+00:00",
                "committer_name": "Administrator",
                "committer_email": "admin@example.com",
                "committed_date": "2023-07-14T19:50:02.000+00:00",
                "trailers": {},
                "web_url": "http://gitlab/root/1234567891-119d1a/-/commit/"
                "31b12e5abe6e4526d7993018ded7f7b56106c6fd",
                "stats": {
                    "additions": 1,
                    "deletions": 1,
                    "total": 2
                },
                "status": None,
                "project_id": 280,
                "last_pipeline": None
            }))

        await self.gitlab.manage_suggestion(123, "string", "approve")

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "POST")

        self.assertEqual(request.url, urljoin(TEST_HOSTNAME,
                                              "api/v4/projects/123/repository"
                                              "/commits"))
        raw_request_data = json.loads(request.data)

        self.assertEqual(raw_request_data["branch"], "main")
        self.assertEqual(raw_request_data["commit_message"], "Add resource"
                         " string to lesson string")
        self.assertEqual(len(raw_request_data["actions"]), 2)

        self.assertEqual(raw_request_data["actions"][0]["action"], "update")
        self.assertEqual(raw_request_data["actions"][0]["file_path"],
                         "track.json")

        self.assertEqual(raw_request_data["actions"][1]["action"], "update")
        self.assertEqual(raw_request_data["actions"][1]["file_path"],
                         "suggestions.json")


class GitlabEditLearningTrackTestCase(GitlabMixin, IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.gitlab.access_token = "test_access"
        self.list_patch = [
            {
                "op": "replace",
                "path": "/title",
                "value": "newTitle4"
            }]

    async def test_edit_learning_track_success(self):

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_name": "track.json",
                "file_path": "track.json",
                "size": 2121,
                "encoding": "base64",
                "content_sha256": "d142e040117e680aafe515a53a33f4baeb49fc38953"
                "5edeb91869a917b173571",
                "ref": "main",
                "blob_id": "f5443b5921eb1b4fa4367eaffa17532b213d47b2",
                "commit_id": "d6fa002403c8515afe0d0f215cfdf7f2631ef518",
                "last_commit_id": "d6fa002403c8515afe0d0f215cfdf7f2631ef518",
                "execute_filemode": "false",
                "content": "ew0KICAic2tpbGxzIjogWw0KICAgICJza2lsbHMiDQogIF0" +
                "sDQogICJsZXNzb25zIjogWw0KICAgIHsNCiAgICAgICJsZXNzb25faWQiO" +
                "iAic29tZVVVSUQiLA0KICAgICAgIm5hbWUiOiAic29tZU5hbWUiLA0KICAg" +
                "ICAgInJlc291cmNlcyI6IFsNCiAgICAgICAgew0KICAgICAgICAgICJsa" +
                "W5rIjogImh0dHA6Ly8uc29tZWxpbmsuY29tIiwNCiAgICAgICAgICAicmV" +
                "zb3VyY2VfaWQiOiAic29tZVVVSUQiLA0KICAgICAgICAgICJ0aXRsZSI6IC" +
                "Jzb21lVGl0bGUiLA0KICAgICAgICAgICJzb3VyY2UiOiAic29tZVRpdGxl" +
                "IiwNCiAgICAgICAgICAicmVzb3VyY2VfdHlwZSI6ICJib29rIiwNCiAgICA" +
                "gICAgICAiZHVyYXRpb24iOiAxMCwNCiAgICAgICAgICAiYWRkZWRCeSI6IC" +
                "JxdWltYmFycmVpcm9zIg0KICAgICAgICB9LA0KICAgICAgICB7DQogICAg" +
                "ICAgICAgImxpbmsiOiAiaHR0cDovLy5zb21lbGluay5jb20iLA0KICAgI" +
                "CAgICAgICJyZXNvdXJjZV9pZCI6ICJzb21lVVVJRCIsDQogICAgICAgIC" +
                "AgInRpdGxlIjogInNvbWVUaXRsZSIsDQogICAgICAgICAgInNvdXJjZSI6" +
                "ICJzb21lVGl0bGUiLA0KICAgICAgICAgICJyZXNvdXJjZV90eXBlIjogIm" +
                "Jvb2siLA0KICAgICAgICAgICJkdXJhdGlvbiI6IDEwLA0KICAgICAgICAgI" +
                "CJhZGRlZEJ5IjogInF1aW1iYXJyZWlyb3MiDQogICAgICAgIH0NCiAgICA" +
                "gIF0NCiAgICB9DQogIF0NCn0="
            }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 1,
                "description": "{\"description\": \"Don't know any python? " +
                "Don't worry! Use your hammer!\", \"career\":" +
                " \"Engineering\"," +
                " \"career_path\": \"Software development\", \"level\":" +
                " \"beginner\"}",
                "name": "newTitle4 1d0049",
                "name_with_namespace": "Administrator / newTitle4 1d0049",
                "path": "how-to-hammer-in-be-6fb1b9",
                "default_branch": "main",
                "tag_list": [],
                "topics": [],
                "builds_access_level": "disabled",
                "visibility": "public",
                "avatar_url": "https://gitlab.mse22.onept.pt:23457/uploads/" +
                "-/system/project/avatar/1/avatar.jpg",
                "owner": {
                    "id": 1,
                    "username": "root",
                    "name": "Administrator",
                    "avatar_url": "https://secure.gravatar.com/avatar" +
                    "/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon"
                }
            }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "id": 1,
                "description": "{\"description\": \"string1\"," +
                " \"career\": \"string2\"}",
                "name": "newTitle3 c58803",
                "path": "how-to-hammer-in-be-6fb1b9",
                "tag_list": [

                ],
                "topics": [

                ],
                "builds_access_level": "disable",
                "avatar_url": "https://gitlab.mse22.onept.pt:23457/uploads/" +
                "-/system/project/avatar/1/avatar.jpg",
                "visibility": "public",
                "owner": {
                    "id": 1,
                    "username": "root",
                    "name": "Administrator",
                    "avatar_url": "https://secure.gravatar.com/avatar" +
                    "/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon"
                }
            }))

        self.fake_session.responses.append(
            FakeResponse(status=200, body_dict={
                "file_path": "track.json",
                "branch": "main"}))

        await self.gitlab.edit_learning_track(
            learning_track_id=1,
            patch=self.list_patch)

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "PUT")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME,
            "/api/v4/projects/1/repository/files/track.json"))

    async def test_post_learning_track_gitlab_error(
            self, ):
        """Gitlab returns 500 when something goes wrong"""
        self.fake_session.responses.append(
            FakeResponse(status=500)
        )

        with self.assertRaisesRegex(
                gitlab_facade.GitlabError, "Gitlab returned status code 500"):
            await self.gitlab.edit_learning_track(1, self.list_patch)


class GitlabDeleteLearningTrackTestCase(GitlabMixin, IsolatedAsyncioTestCase):

    async def test_delete_learning_track_404(self):
        """Gitlab returns 404"""
        self.fake_session.responses.append(
            FakeResponse(status=404)
        )

        with self.assertRaisesRegex(expected_exception=LookupError,
                                    expected_regex="123456"):
            await self.gitlab.delete_learning_track("123456")

    async def test_delete_learning_track(self):
        self.fake_session.responses.append(
            FakeResponse(status=202))

        await self.gitlab.delete_learning_track("123456")

        request = self.fake_session.requests.pop()

        self.assertEqual(request.method, "DELETE")

        self.assertEqual(request.url, urljoin(
            TEST_HOSTNAME,
            "/api/v4/projects/123456"))


class ResizeImageTestCase(
    GitlabMixin,
    IsolatedAsyncioTestCase,
):
    def _get_file(self, filename: str) -> bytearray:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        image_path = os.path.join(current_dir, f"images/{filename}")
        with open(image_path, "rb") as image:
            thumbnail_image = image.read()

        return thumbnail_image

    async def test_jpeg_small_jpeg(self):
        image = self._get_file("image.jpg")

        image = GitlabImage.get_image(
            image,
            gitlab_facade.API_MAX_IMAGE_SIZE,
            gitlab_facade.GITLAB_MAX_IMAGE_SIZE
        )

        self.assertLessEqual(
            len(image),
            gitlab_facade.GITLAB_MAX_IMAGE_SIZE
        )

    async def test_jpeg_too_big(self):
        image = self._get_file("image_4MB.jpg")

        with self.assertRaises(gitlab_facade.InvalidFileSizeError):
            image = GitlabImage.get_image(
                image,
                gitlab_facade.API_MAX_IMAGE_SIZE,
                gitlab_facade.GITLAB_MAX_IMAGE_SIZE
            )

    async def test_jpeg_big(self):
        image = self._get_file("image_2MB.jpg")

        image = GitlabImage.get_image(
            image,
            gitlab_facade.API_MAX_IMAGE_SIZE,
            gitlab_facade.GITLAB_MAX_IMAGE_SIZE
        )

        self.assertLessEqual(
            len(image),
            gitlab_facade.GITLAB_MAX_IMAGE_SIZE
        )

    async def test_invalid_image(self):
        image = "file"

        with self.assertRaisesRegex(ValueError, "Invalid image."):
            image = GitlabImage.get_image(
                image,
                gitlab_facade.API_MAX_IMAGE_SIZE,
                gitlab_facade.GITLAB_MAX_IMAGE_SIZE
            )


if __name__ == "__main__":  # pragma: no cover
    from unittest import main
    main()

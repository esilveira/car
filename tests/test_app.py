import asyncio
import base64
import os
from types import SimpleNamespace
import unittest
from async_asgi_testclient import TestClient
from unittest import IsolatedAsyncioTestCase
from unittest import mock

from app.main import create_app
import app.main as app_main
from app import gitlab_facade as gl
from datetime import datetime, UTC, timedelta
from app.serialize import from_dict

DEFAULT_EXPIRATION_DATE = datetime(1970, 1, 1, tzinfo=UTC)


def create_mock_gitlab():
    class MockGitlab(gl.Gitlab):
        access_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6Ikp"
            "XVCJ9.eyJnaXRsYWJfYWNjZXNzX3Rva2VuIjoidG"
            "9rZW4iLCJleHAiOjEzNzQzODk1MzQ3Miwic3ViI"
            "joyLCJhdWQiOiJjYXJlZXJjZW50ZXIiL"
            "CJpc3MiOiJjYXJlZXJjZW50ZXIiLCJpYX"
            "QiOjN9.OeehPoaLq3u43ALzA3Ypjs_jIJzx9Ui"
            "ygLGazftvKxM")

    gitlab = mock.create_autospec(
        MockGitlab,
        spec_set=True
    )

    user_info = gl.UserInfo(
        1,
        "testname",
        "testusername",
        "testemail"
    )

    gitlab.return_value.get_user_info.return_value = user_info

    gitlab.return_value.login.return_value = (
        gl.GitlabToken(
            gl.GitlabAccessToken("accesstoken"),
            "mytype",
            expiration_date=DEFAULT_EXPIRATION_DATE,
            refresh_token=gl.GitlabRefreshToken("refreshtoken")
        ),
        user_info)

    gitlab.return_value.get_learning_track.return_value = gl.LearningTrackData(
        learning_track_id=12345,
        is_draft=False,
        is_private=True,
        title='str1',
        career='string',
        career_path='someCareerPath',
        description='string',
        thumbnail_image='None',
        level=gl.LevelEnum.beginner,
        tags=['string'],
        skills=['skills'],
        createdBy=gl.Creator(
            username='antonio',
            name='antonio antonio',
            avatar="https://www.gravatar.com/avatar/"
            "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
            creator_id=15),
        lessons=[
            gl.Lesson(lesson_id='someUUID',
                      name='someName',
                      resources=[
                          gl.Resource(resource_id='someUUID',
                                      link='http://.somelink.com',
                                      title='someTitle',
                                      source='someTitle',
                                      resource_type=gl.ResourceTypeEnum.book,
                                      duration=10,
                                      addedBy='quimbarreiros'),
                          gl.Resource(resource_id='someUUID',
                                      link='http://.somelink.com',
                                      title='someTitle',
                                      source='someTitle',
                                      resource_type=gl.ResourceTypeEnum.book,
                                      duration=10,
                                      addedBy='quimbarreiros')])])

    learning_tracks_result = gl.LearningTrackMetadata(
        learning_track_id=12345,
        is_draft=False,
        is_private=True,
        title='str1',
        career='string',
        description='string',
        thumbnail_image='None',
        tags=['string'],
        createdBy=gl.Creator(
            username='antonio',
            name='antonio antonio',
            avatar="https://www.gravatar.com/avatar/"
            "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
            creator_id=15),
        career_path="someCareerPath",
        level=gl.LevelEnum.beginner)
    learning_tracks_list = [learning_tracks_result]

    gitlab.return_value.get_learning_tracks.return_value = (
        gl.AllLearningTracks(
            hasResults=True,
            learning_tracks=learning_tracks_list
        ))
    gitlab.return_value.post_learning_track.return_value = 12345

    gitlab.return_value.get_learning_tracks_progress.return_value = [
        gl.UserProgress(
            learning_track_id=12345,
            progress=[
                gl.ResourceProgress(
                    resource_id='someUUID',
                    completed=True),
                gl.ResourceProgress(
                    resource_id='someUUID1',
                    completed=True)
            ]),
        gl.UserProgress(
            learning_track_id=123456,
            progress=[
                gl.ResourceProgress(
                    resource_id='someUUID',
                    completed=True),
                gl.ResourceProgress(
                    resource_id='someUUID1',
                    completed=True)
            ])]

    gitlab.return_value.get_learning_track_progress.return_value = [
        gl.ResourceProgress(
            resource_id='someUUID',
            completed=True),
        gl.ResourceProgress(
            resource_id='someUUID1',
            completed=True)
    ]

    gitlab.return_value.put_learning_track_progress.return_value = None

    gitlab.return_value.get_learning_track_commits.return_value = [
        gl.LearningTrackCommit(
            change_id='9e023e77f0f7b53c17419358aadfcb787921404d',
            # short_id='9e023e77',
            # created_at='2023-07-09T14:25:58.000+00:00',
            # parent_ids=[],
            # title='Create learning track',
            change_message='{"description": "string1", "career": "string2"}',
            # author_name='antonio antonio',
            # author_email='admin@example.com',
            # authored_date='2023-07-09T14:25:58.000+00:00',
            # committer_name='Administrator',
            # committer_email='admin@example.com',
            change_date='2023-07-09T14:25:58.000+00:00',
            # trailers={},
            # web_url="http://gitlab.example.com/root/1234567891-2a31b4/"
            # "-/commit/9e023e77f0f7b53c17419358aadfcb787921404d"
        ),
    ]

    gitlab.return_value.copy_learning_track.return_value = 123

    gitlab.return_value.revert_learning_track.return_value = None

    gitlab.return_value.get_open_suggestions.return_value = [
        gl.LearningTrackSuggestion(
            suggestion_id=12345,
            lesson_id=123,
            name="lesson name",
            description="suggestion description",
            resource=gl.Resource(resource_id='someUUID',
                                 link='http://.somelink.com',
                                 title='someTitle',
                                 source='someTitle',
                                 resource_type=gl.ResourceTypeEnum.book,
                                 duration=10,
                                 addedBy='quimbarreiros'))]

    gitlab.return_value.post_suggestions.return_value = None

    gitlab.return_value.manage_suggestion.return_value = None

    gitlab.return_value.edit_learning_track.return_value = 200

    gitlab.return_value.delete_learning_track.return_value = None

    return gitlab


class AppTestMixin(IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.app = create_app()
        self.gitlab_patch = mock.patch(
            "app.gitlab_facade.Gitlab",
            new=create_mock_gitlab()
        )
        self.gitlab = self.gitlab_patch.start()
        self.app_settings = SimpleNamespace(
            jwt_secret="test_jwt_secret",
            gitlab_admin_token="test_admin_token",
            loglevel="INFO",
            register_enabled=True)
        self.gitlab_settings = SimpleNamespace(
            gitlab_hostname="test_hostname")

        patcher = mock.patch.multiple(
            "app.main", AppSettings=lambda: self.app_settings,
            _GitlabSettings=lambda: self.gitlab_settings)
        patcher.start()
        self.addCleanup(patcher.stop)

        app_main.get_app_settings.reset()
        app_main.get_gitlab_config.reset()

        self.gitlab_instance = self.gitlab.return_value

    def tearDown(self):
        super().tearDown()
        self.gitlab_patch.stop()


class TestClientMixin(AppTestMixin, IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.client = TestClient(self.app)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.client.__aenter__()
        return self

    async def asyncTearDown(self):
        await self.client.__aexit__(None, None, None)
        return await super().asyncTearDown()


class TestClientAuthenticatedMixin(AppTestMixin, IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.client = TestClient(self.app)
        self.client.headers = {
            "Authorization": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJnaXRsYWJ"
            "fYWNjZXNzX3Rva2VuIjoidG9rZW4iLCJleHAiOjEzNzQzODk1MzQ3Miwic3ViIjoy"
            "LCJhdWQiOiJjYXJlZXJjZW50ZXIiLCJpc3MiOiJjYXJlZXJjZW50ZXIiLCJpYXQiO"
            "jN9.DAidB8i_FpPnVNnMxoZWvVOLNE2hLRHG6qUjExAb21Y"
        }

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.client.__aenter__()
        return self

    async def asyncTearDown(self):
        await self.client.__aexit__(None, None, None)
        return await super().asyncTearDown()


class AppLoginTestCase(TestClientMixin, AppTestMixin, IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        encode_token_patcher = mock.patch(
            "app.main.encode_token", autospec=True, spec_set=True)
        self.encode_token = encode_token_patcher.start()
        self.encode_token.side_effect = ["test_token", "test_refresh_token"]
        self.addCleanup(encode_token_patcher.stop)

    async def test_login(self):
        response = await self.client.post(
            "/auth/login", json={"username": "test", "password": "test"})
        self.assertEqual(response.status_code, 200)

        self.gitlab_instance.login.assert_called_once_with(
            username="test", password="test")

        response_value = response.json()
        self.assertEqual(response_value["access_token"], "test_token")
        self.assertEqual(response_value["refresh_token"], "test_refresh_token")
        self.assertEqual(response_value["user_info"], {
            "id": 1,
            "name": "testname",
            "username": "testusername",
            "email": "testemail"
        }
        )
        self.assertAlmostEqual(
            (DEFAULT_EXPIRATION_DATE - datetime.now(UTC) -
             timedelta(minutes=5)).total_seconds(),
            response_value["expires_in"], delta=1)

    async def test_login_with_invalid_credentials(self):
        self.gitlab_instance.login.side_effect = gl.InvalidCredentialsError()
        response = await self.client.post(
            "/auth/login", json={"username": "test1", "password": "test1"})
        self.assertEqual(response.status_code, 401)

    async def test_login_gitlab_unavailable(self):
        """Gitlab timeout or unavailable"""
        self.gitlab_instance.login.side_effect = asyncio.TimeoutError()

        with self.assertLogs("backend.main", level="WARNING") as cm:
            response = await self.client.post(
                "/auth/login", json={"username": "test1", "password": "test1"})

        self.assertIn("Timeout while logging in user test1", cm.output[0])

        self.assertEqual(response.status_code, 504)

    async def test_login_gitlab_error(self):
        """Any unknown error thrown by gitlab"""
        self.gitlab_instance.login.side_effect = gl.GitlabError()

        with self.assertLogs("backend.main", level="ERROR") as cm:
            response = await self.client.post(
                "/auth/login", json={"username": "test1", "password": "test1"})

        self.assertIn("Error while logging in user test1", cm.output[0])

        self.assertEqual(response.status_code, 502)

    async def test_login_gitlab_invalid_input(self):
        response = await self.client.post(
            "/auth/login", json={"quim barreiros": "test1"})
        self.assertEqual(response.status_code, 422)
        response = await self.client.post(
            "/auth/login", data="lsdfighaujiodfns",
            headers={"Content-Type": "blah"})

        # Fast API bug, 422 instead of 400 is sent
        # https://github.com/tiangolo/fastapi/issues/643
        self.assertEqual(response.status_code, 422)


class AppRegisterTestCase(TestClientMixin, AppTestMixin,
                          IsolatedAsyncioTestCase):
    async def test_register(self):
        response = await self.client.post(
            "/auth/register", json={
                "username": "test", "password": "password",
                "email": "test@example.com", "full_name": "Test User"})

        self.assertEqual(response.status_code, 201)

        self.gitlab_instance.register.assert_called_once_with(
            gl.RegisterData(
                username='test', password='password',
                email='test@example.com', name='Test User'))

    async def test_register_entity_already_exists(self):
        self.gitlab_instance.register.side_effect = gl.EntityAlreadyExists(
            "username", entity="test"
        )

        with self.assertLogs("backend.main", level="DEBUG") as cm:
            response = await self.client.post(
                "/auth/register", json={
                    "username": "test", "password": "password",
                    "email": "test@example.com", "full_name": "Test User"})

        self.assertIn("Entitiy already exists username: test", cm.output[0])

        self.assertEqual(response.status_code, 409)

        self.gitlab_instance.register.side_effect = gl.EntityAlreadyExists(
            "email", entity="test@example.com"
        )

        with self.assertLogs("backend.main", level="DEBUG") as cm:
            response = await self.client.post(
                "/auth/register", json={
                    "username": "test", "password": "password",
                    "email": "test@example.com", "full_name": "Test User"})

        self.assertIn("Entitiy already exists email: test@example.com",
                      cm.output[0])

        self.assertEqual(response.status_code, 409)

    async def test_register_invalid_data(self):
        self.gitlab_instance.register.side_effect = ValueError()

        response = await self.client.post(
            "/auth/register", json={
                "username": "test", "password": "password",
                "email": "test@example.com", "full_name": "Test User"})

        self.assertEqual(response.status_code, 400)

    async def test_register_gitlab_unavailable(self):
        """Gitlab timeout or unavailable"""
        self.gitlab_instance.register.side_effect = asyncio.TimeoutError()

        with self.assertLogs("backend.main", level="WARNING") as cm:
            response = await self.client.post(
                "/auth/register", json={
                    "username": "test", "password": "password",
                    "email": "test@example.com", "full_name": "Test User"})

        self.assertIn("Timeout while registering user test.", cm.output[0])

        self.assertEqual(response.status_code, 504)

    # TODO: Need to check if FastAPI logs unhandled exceptions or is the
    # responsibility of uvicorn / gunicorn.

    @unittest.skip("GitlabError is not logged, "
                   "perhaps because of the asgi test client.")
    async def test_register_gitlab_error(self):  # pragma: no cover
        """Any unknown error thrown by gitlab"""
        self.gitlab_instance.register.side_effect = gl.GitlabError()

        with self.assertLogs("backend.main", level="ERROR") as cm:
            response = await self.client.post(
                "/auth/register", json={
                    "username": "test", "password": "password",
                    "email": "test@example.com", "full_name": "Test User"})

        self.assertIn("Error while registering in user test1", cm.output[0])

        self.assertEqual(response.status_code, 502)

    async def test_register_invalid_json(self):
        """Invalid json sent to the endpoint"""
        response = await self.client.post(
            "/auth/register", json={
                "username": "test"})

        self.assertEqual(response.status_code, 422)


class AppGetLearningTrackTestCase(TestClientAuthenticatedMixin, AppTestMixin,
                                  IsolatedAsyncioTestCase):

    async def test_get_learning_track_success(self):

        response = await self.client.get(
            "/learning-tracks/12345")
        self.assertEqual(response.status_code, 200)

        self.assertEqual(from_dict(datacls=gl.LearningTrackData,
                                   data=response.json()),
                         self.gitlab_instance.get_learning_track.return_value)

    async def test_get_learning_track_not_found(self):

        self.gitlab_instance.get_learning_track.side_effect = \
            gl.GitlabLookupError(resource_type=gl.LookupErrors.learning_track)

        response = await self.client.get(
            "/learning-tracks/123456")
        self.assertEqual(response.status_code, 404)

    async def test_get_all_learning_track_success(self):

        response = await self.client.get(
            "/learning-tracks?search=someSearch")
        self.assertEqual(response.status_code, 200)

        self.assertEqual(from_dict(datacls=gl.AllLearningTracks,
                                   data=response.json()),
                         self.gitlab_instance.get_learning_tracks.return_value)


class AppPostLearningTrackTestCase(TestClientAuthenticatedMixin, AppTestMixin,
                                   IsolatedAsyncioTestCase):

    async def test_post_learning_track_success(self):

        # Get the directory path of the current file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Construct the path to the image file
        image_path = os.path.join(current_dir, "images/image.jpg")

        image = open(image_path, "rb")
        thumbnail_image = base64.b64encode(image.read()).decode('utf-8')
        image.close()

        learning_track_data = {
            "learning_track_id": 12345,
            "is_draft": False,
            "is_private": True,
            "title": "str1",
            "career": "string",
            "career_path": "someCareerPath",
            "description": "string",
            "thumbnail_image": thumbnail_image,
            "level": "beginner",
            "tags": ["string"],
            "skills": ["skills"],
            "createdBy": {
                "username": "antonio",
                "name": "antonio antonio",
                "avatar": "https://www.gravatar.com/avatar/"
                "b4f1e541550ac1c63c1e7c90932f7f45?s=80&d=identicon",
                "creator_id": 15
            },
            "lessons": [
                {
                    "lesson_id": "someUUID",
                    "name": "someName",
                    "resources": [
                        {
                            "resource_id": "someUUID",
                            "link": "http://.somelink.com",
                            "title": "someTitle",
                            "source": "someTitle",
                            "resource_type": "book",
                            "duration": 10,
                            "addedBy": "quimbarreiros"
                        }
                    ]
                }
            ]
        }

        response = await self.client.post(
            "/learning-tracks", json=learning_track_data)

        self.assertEqual(response.status_code, 201)

        self.assertEqual(12345,
                         self.gitlab_instance.post_learning_track.return_value)

    async def test_post_learning_track_invalid_learning_track(self):

        self.gitlab_instance.post_learning_track.side_effect = (
            ValueError("Invalid learning track.")
        )

        response = await self.client.post(
            "/learning-tracks/", json={})

        self.assertEqual(response.status_code, 422)


class UserProgressTestCase(TestClientAuthenticatedMixin,
                           AppTestMixin,
                           IsolatedAsyncioTestCase):

    async def test_get_learning_tracks_progress_success(self):
        response = await self.client.get(
            "/users/12345/progress")

        self.assertEqual(response.status_code, 200)

        self.assertEqual(
            from_dict(datacls=gl.UserProgress,
                      data=response.json()[0]),
            self.gitlab_instance.get_learning_tracks_progress.return_value[0])

    async def test_get_learning_tracks_error(self):

        self.gitlab_instance.get_learning_tracks_progress.side_effect = (
            ValueError("Error getting the user's current progress.")
        )

        response = await self.client.get(
            "/users/12345/progress")

        self.assertEqual(response.status_code, 400)

    async def test_get_learning_tracks_timeout(self):

        self.gitlab_instance.get_learning_tracks_progress.side_effect = (
            asyncio.TimeoutError()
        )

        response = await self.client.get(
            "/users/12345/progress")

        self.assertEqual(response.status_code, 504)

    async def test_get_learning_track_progress_success(self):
        response = await self.client.get(
            "/users/12345/progress/12345")

        self.assertEqual(response.status_code, 200)

        self.assertEqual(
            from_dict(datacls=gl.ResourceProgress,
                      data=response.json()["progress"][0]),
            self.gitlab_instance.get_learning_track_progress.return_value[0])

    async def test_get_learning_track_progress_error(self):

        self.gitlab_instance.get_learning_track_progress.side_effect = (
            LookupError("Error getting the user's current progress.")
        )

        response = await self.client.get("/users/12345/progress/12345")

        self.assertEqual(response.status_code, 404)

    async def test_get_learning_track_timeout(self):

        self.gitlab_instance.get_learning_track_progress.side_effect = (
            asyncio.TimeoutError()
        )

        response = await self.client.get(
            "/users/12345/progress/12345")

        self.assertEqual(response.status_code, 504)

    async def test_put_learning_track_progress_success(self):

        response = await self.client.put(
            "/users/12345/progress/12345", json={
                "progress": [
                    {
                        "resource_id": "someUUID",
                        "completed": True,
                    }
                ]
            })

        self.assertEqual(response.status_code, 200)

    async def test_put_learning_track_progress_timeout(self):

        self.gitlab_instance.put_learning_track_progress.side_effect = (
            asyncio.TimeoutError()
        )

        response = await self.client.put(
            "/users/12345/progress/12345", json={
                "progress": [
                    {
                        "resource_id": "someUUID",
                        "completed": True,
                    }
                ]
            })

        self.assertEqual(response.status_code, 504)

    async def test_put_learning_track_progress_error(self):

        self.gitlab_instance.put_learning_track_progress.side_effect = (
            LookupError("Learning track not found.")
        )

        response = await self.client.put(
            "/users/12345/progress/12345", json={
                "progress": [
                    {
                        "resource_id": "someUUID",
                        "completed": True,
                    }
                ]
            })

        self.assertEqual(response.status_code, 404)

    async def test_healthcheck(self):
        response = await self.client.get("/-/health")
        self.assertEqual(response.status_code, 200)

    async def test_get_learning_track_history_sucess(self):
        response = await self.client.get("/learning-tracks/12345/history")
        self.assertEqual(response.status_code, 200)

    async def test_get_learning_track_history_error(self):
        self.gitlab_instance.get_learning_track_commits.side_effect = (
            gl.GitlabLookupError(resource_type=gl.LookupErrors.learning_track)
        )
        response = await self.client.get("/learning-tracks/999/history")
        self.assertEqual(response.status_code, 404)

    async def test_get_learning_track_commit_id_sucess(self):
        response = await self.client.get(
            "/learning-tracks/12345/history/"
            "9e023e77f0f7b53c17419358aadfcb787921404d"
        )
        self.assertEqual(response.status_code, 200)

    async def test_get_learning_track_commit_id_learning_track_found(self):
        self.gitlab_instance.get_learning_track.side_effect = (
            gl.GitlabLookupError(resource_type=gl.LookupErrors.learning_track)
        )
        response = await self.client.get("/learning-tracks/999/history/abc")
        self.assertEqual(response.status_code, 404)

    async def test_get_learning_track_commit_id_commit_not_found(self):
        self.gitlab_instance.get_learning_track.side_effect = (
            gl.GitlabLookupError(resource_type=gl.LookupErrors.commit)
        )
        response = await self.client.get("/learning-tracks/12345/history/abc")
        self.assertEqual(response.status_code, 404)


class CopyLearningTrackTestCase(TestClientAuthenticatedMixin, AppTestMixin,
                                IsolatedAsyncioTestCase):

    async def test_copy_learning_track(self):
        response = await self.client.post("/learning-tracks/12345/copy")
        self.assertEqual(response.status_code, 200)

    async def test_copy_learning_track_timeout(self):
        self.gitlab_instance.copy_learning_track.side_effect = (
            asyncio.TimeoutError()
        )
        response = await self.client.post("/learning-tracks/12345/copy")
        self.assertEqual(response.status_code, 504)

    async def test_copy_learning_track_error(self):
        self.gitlab_instance.copy_learning_track.side_effect = (
            LookupError("Learning track not found.")
        )
        response = await self.client.post("/learning-tracks/12345/copy")
        self.assertEqual(response.status_code, 404)


class RevertLearningTrackTestCase(TestClientAuthenticatedMixin,
                                  AppTestMixin, IsolatedAsyncioTestCase):

    async def test_revert_learning_track(self):
        response = await self.client.post(
            "/learning-tracks/12345/history/"
            "df9f6c4b5c5eb1f462daca015410f9cb34a2e6f0")
        self.assertEqual(response.status_code, 201)

    async def test_revert_learning_track_timeout(self):
        self.gitlab_instance.revert_learning_track.side_effect = (
            asyncio.TimeoutError()
        )
        response = await self.client.post(
            "/learning-tracks/12345/history/"
            "df9f6c4b5c5eb1f462daca015410f9cb34a2e6f0")
        self.assertEqual(response.status_code, 504)

    async def test_revert_learning_track_error(self):
        self.gitlab_instance.revert_learning_track.side_effect = (
            LookupError("Learning track not found.")
        )
        response = await self.client.post(
            "/learning-tracks/12/history/"
            "df9f6c4b5c5eb1f462daca015410f9cb34a2e6f0")
        self.assertEqual(response.status_code, 404)


class LearningTrackSuggestionTestCase(TestClientAuthenticatedMixin,
                                      AppTestMixin, IsolatedAsyncioTestCase):

    async def test_get_learning_track_suggestions(self):
        response = await self.client.get("/learning-tracks/123/"
                                         "suggestions")

        response_value = response.json()
        self.assertEqual(response_value[0]["lesson_id"], "123")
        self.assertEqual(response_value[0]["name"], "lesson name")
        self.assertEqual(response_value[0]["description"],
                         "suggestion description")
        self.assertEqual(response_value[0]["suggestion_id"], "12345")
        self.assertEqual(response_value[0]["resource"]["resource_id"],
                         "someUUID")
        self.assertEqual(response_value[0]["resource"]["link"],
                         "http://.somelink.com")
        self.assertEqual(response_value[0]["resource"]["title"],
                         "someTitle")
        self.assertEqual(response_value[0]["resource"]["resource_type"],
                         "book")
        self.assertEqual(response_value[0]["resource"]["duration"], 10)
        self.assertEqual(response_value[0]["resource"]["addedBy"],
                         "quimbarreiros")

        self.assertEqual(response.status_code, 200)

    async def test_get_learning_track_suggestions_timeout(self):
        self.gitlab_instance.get_open_suggestions.side_effect = (
            asyncio.TimeoutError()
        )
        response = await self.client.get("/learning-tracks/123/"
                                         "suggestions")
        self.assertEqual(response.status_code, 504)

    async def test_get_learning_track_suggestions_error(self):
        self.gitlab_instance.get_open_suggestions.side_effect = (
            LookupError("Learning track not found.")
        )
        response = await self.client.get("/learning-tracks/123/"
                                         "suggestions")
        self.assertEqual(response.status_code, 404)

    async def test_get_learning_track_suggestions_gitlab_error(self):
        self.gitlab_instance.get_open_suggestions.side_effect = (
            gl.GitlabError("Gitlab error.")
        )
        response = await self.client.get("/learning-tracks/123/"
                                         "suggestions")

        self.assertEqual(response.status_code, 502)

    async def test_post_learning_track_suggestions(self):

        response = await self.client.post(
            "/learning-tracks/123/suggestions", json=[
                {
                    "lesson_id": "string3213231",
                    "name": "string",
                    "description": "dadxadxas",
                    "resource": {
                            "resource_id": "string",
                            "link": "string",
                            "title": "string",
                            "source": "string",
                            "resource_type": "book",
                            "duration": 0,
                            "addedBy": "string"
                    }
                }
            ]
        )

        self.assertEqual(response.status_code, 204)

    async def test_post_learning_track_suggestions_timeout(self):

        self.gitlab_instance.post_suggestions.side_effect = (
            asyncio.TimeoutError()
        )

        response = await self.client.post(
            "/learning-tracks/123/suggestions", json=[
                {
                    "lesson_id": "string3213231",
                    "name": "string",
                    "description": "dadxadxas",
                    "resource": {
                            "resource_id": "string",
                            "link": "string",
                            "title": "string",
                            "source": "string",
                            "resource_type": "book",
                            "duration": 0,
                            "addedBy": "string"
                    }
                }
            ]
        )

        self.assertEqual(response.status_code, 504)

    async def test_post_learning_track_suggestions_not_found_error(self):

        self.gitlab_instance.post_suggestions.side_effect = (
            LookupError("Learning track not found.")
        )

        response = await self.client.post(
            "/learning-tracks/123/suggestions", json=[
                {
                    "lesson_id": "string3213231",
                    "name": "string",
                    "description": "dadxadxas",
                    "resource": {
                            "resource_id": "string",
                            "link": "string",
                            "title": "string",
                            "source": "string",
                            "resource_type": "book",
                            "duration": 0,
                            "addedBy": "string"
                    }
                }
            ]
        )

        self.assertEqual(response.status_code, 404)

    async def test_post_learning_track_suggestions_internal_error(self):

        self.gitlab_instance.post_suggestions.side_effect = (
            gl.GitlabError("Gitlab error.")
        )

        response = await self.client.post(
            "/learning-tracks/123/suggestions", json=[
                {
                    "lesson_id": "string3213231",
                    "name": "string",
                    "description": "dadxadxas",
                    "resource": {
                            "resource_id": "string",
                            "link": "string",
                            "title": "string",
                            "source": "string",
                            "resource_type": "book",
                            "duration": 0,
                            "addedBy": "string"
                    }
                }
            ]
        )

        self.assertEqual(response.status_code, 502)

    async def test_manage_suggestion_approve(self):

        response = await self.client.put(
            "/learning-tracks/123/suggestions/12345?action=approve",
        )

        self.assertEqual(response.status_code, 201)

    async def test_manage_suggestion_reject(self):

        response = await self.client.put(
            "/learning-tracks/123/suggestions/12345?action=reject",
        )

        self.assertEqual(response.status_code, 201)

    async def test_manage_suggestion_invalid_action(self):

        response = await self.client.put(
            "/learning-tracks/123/suggestions/12345?action=invalid",
        )

        self.assertEqual(response.status_code, 400)

    async def test_manage_suggestion_timeout(self):

        self.gitlab_instance.manage_suggestion.side_effect = (
            asyncio.TimeoutError()
        )

        response = await self.client.put(
            "/learning-tracks/123/suggestions/12345?action=approve",
        )

        self.assertEqual(response.status_code, 504)

    async def test_manage_suggestion_not_found_error(self):

        self.gitlab_instance.manage_suggestion.side_effect = (
            LookupError("Learning track not found.")
        )

        response = await self.client.put(
            "/learning-tracks/123/suggestions/12345?action=approve",
        )

        self.assertEqual(response.status_code, 404)

    async def test_manage_suggestion_internal_error(self):

        self.gitlab_instance.manage_suggestion.side_effect = (
            gl.GitlabError("Gitlab error.")
        )

        response = await self.client.put(
            "/learning-tracks/123/suggestions/12345?action=approve",
        )

        self.assertEqual(response.status_code, 502)


class EditLearningTrackTestCase(TestClientAuthenticatedMixin, AppTestMixin,
                                IsolatedAsyncioTestCase):
    async def test_edit_learning_track_success(self):

        response = await self.client.patch(
            "/learning-tracks/1",
            json=[
                {
                    "op": "replace",
                    "path": "/title",
                    "value": "newTitle3"
                }
            ])

        self.assertEqual(response.status_code, 204)

        self.assertEqual(200,
                         self.gitlab_instance.edit_learning_track.return_value)

    async def test_edit_learning_track_empty_patch(self):

        response = await self.client.patch(
            "/learning-tracks/1",
            json=[])

        self.assertEqual(response.status_code, 204)

    async def test_edit_learning_track_timeout(self):
        self.gitlab_instance.edit_learning_track.side_effect = (
            asyncio.TimeoutError()
        )
        response = await self.client.patch("/learning-tracks/1",
                                           json=[
                                               {
                                                   "op": "replace",
                                                   "path": "/title",
                                                   "value": "newTitle3"
                                               }
                                           ])
        self.assertEqual(response.status_code, 504)

    async def test_edit_learning_track_error(self):
        self.gitlab_instance.edit_learning_track.side_effect = (
            LookupError("Learning track not found.")
        )
        response = await self.client.patch("/learning-tracks/1",
                                           json=[
                                               {
                                                   "op": "replace",
                                                   "path": "/title",
                                                   "value": "newTitle3"
                                               }
                                           ])
        self.assertEqual(response.status_code, 404)


class DeleteLearningTrackTestCase(TestClientAuthenticatedMixin,
                                  AppTestMixin, IsolatedAsyncioTestCase):

    async def test_delete_learning_track_success(self):
        response = await self.client.delete("/learning-tracks/1")
        self.assertEqual(response.status_code, 204)

    async def test_delete_learning_track_timeout(self):
        self.gitlab_instance.delete_learning_track.side_effect = (
            asyncio.TimeoutError()
        )
        response = await self.client.delete("/learning-tracks/1")
        self.assertEqual(response.status_code, 504)

    async def test_delete_learning_track_error(self):
        self.gitlab_instance.delete_learning_track.side_effect = (
            LookupError("Learning track not found.")
        )
        response = await self.client.delete("/learning-tracks/1")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

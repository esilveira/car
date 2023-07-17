from tests.test_gitlab import GitlabLoginTestCase
from tests.test_gitlab import GitlabRegisterTestCase
from tests.test_gitlab import GitlabGetLearningTrackTestCase
from tests.test_tokens import TokensTestCase
from tests.test_gitlab import GitlabPostLearningTrackTestCase
from tests.test_gitlab import GitlabUserProgressTestCase
from tests.test_gitlab import GitlabCopyLearningTrackTestCase
from tests.test_gitlab import GitlabRootLongTermTestCase
from tests.test_gitlab import GitlabSuggestionsTestCase
from tests.test_gitlab import GitlabDeleteLearningTrackTestCase
from tests.test_gitlab import ResizeImageTestCase
from tests.test_app import AppLoginTestCase
from tests.test_app import AppRegisterTestCase
from tests.test_app import AppGetLearningTrackTestCase
from tests.test_app import AppPostLearningTrackTestCase
from tests.test_app import UserProgressTestCase
from tests.test_app import CopyLearningTrackTestCase
from tests.test_app import LearningTrackSuggestionTestCase
from tests.test_app import DeleteLearningTrackTestCase

__all__ = ['GitlabLoginTestCase', 'GitlabRegisterTestCase',
           'TokensTestCase', "AppLoginTestCase", "AppRegisterTestCase",
           "AppGetLearningTrackTestCase", "GitlabGetLearningTrackTestCase",
           "GitlabPostLearningTrackTestCase", "AppPostLearningTrackTestCase",
           "UserProgressTestCase", "GitlabUserProgressTestCase",
           "CopyLearningTrackTestCase", "GitlabCopyLearningTrackTestCase",
           "GitlabRootLongTermTestCase", "LearningTrackSuggestionTestCase",
           "GitlabSuggestionsTestCase", "DeleteLearningTrackTestCase",
           "GitlabDeleteLearningTrackTestCase", "ResizeImageTestCase"]

import datetime
from dataclasses import dataclass
from enum import Enum


@dataclass
class UserInfo:
    """User information

    Loosely based on
    https://docs.gitlab.com/ee/integration/openid_connect_provider.html
    """

    id: int  # ID of the user
    name: str  # Full name of the user
    username: str
    email: str | None


@dataclass
class RegisterData:
    """Data to register a user.

    Attributes:
        username: Username of the user.
        password: Password of the user.
        email: Email of the user.
        full_name: Full name of the user.
    """

    username: str
    password: str
    email: str
    name: str


@dataclass
class Creator:
    """Data of a Creator.

    Attributes:
        username: Username of the creator.
        name: Name of the cretor.
        avatar: Avatar of the creator.
    """

    username: str
    name: str
    avatar: str
    creator_id: int


class ResourceTypeEnum(Enum):
    article = "article"
    book = "book"
    course = "course"
    video = "video"


@dataclass
class Resource:
    """Data of a Resource.

    Attributes:
        id: Unique identifier for the resource
        link: URL to the resource
        title: Title of the resource
        source: Source of the resource
        type: Type of the resource (e.g., video, article, etc.)
        duration: Duration of the resource in minutes
        addedBy: Name of the user who added the resources
    """

    resource_id: str
    link: str
    title: str
    source: str
    resource_type: ResourceTypeEnum
    duration: int
    addedBy: str

    def __post_init__(self):
        self.duration = int(self.duration)


@dataclass
class Lesson:
    """Data of a Lesson.

    Attributes:
        id: Unique identifier for the resource.
        name: Name of the lesson.
        resources: List of resources.
    """

    lesson_id: str
    name: str
    resources: list[Resource]


class LevelEnum(Enum):
    beginner = "beginner"
    intermediate = "intermediate"
    expert = "expert"


@dataclass
class LearningTrackData:
    """Data of a Learning Track.

    Attributes:
        is_draft: Indicates whether the learning track is a draft or published
        is_private: Indicates whether the learning track
        is private or publicly accessible
        title: Title of the learning track
        career: Associated career for the learning track
        career_path: Associated career path for the learning track
        description: Description of the learning track
        thumbnail_image: URL to the thumbnail image of the learning track
        level: Difficulty level of the learning track
            (beginner, intermediate, or expert)
        tags: List of tags related to the learning track
        skills: List of skills that the learning track aims to teach
        learning_track_id: Unique identifier for the learning track
        createdBy: Creator of the Learning Track
        lessons: List of Lesson in this Learning Track
    """

    is_draft: bool
    is_private: bool
    title: str
    career: str
    career_path: str
    description: str
    thumbnail_image: str
    level: LevelEnum
    tags: list[str]
    skills: list[str]
    lessons: list[Lesson]
    learning_track_id: int | None = None
    createdBy: Creator | None = None


@dataclass
class LearningTrackSuggestion:
    """
    Data of a Learning Track Suggestion.

    Attributes:
        lesson_id: Unique identifier for the lesson
        name: Name of the lesson
        resource: The resource to be updated
        description: Description of the suggestion
        suggestion_id: Unique identifier for the suggestion
    """

    lesson_id: str
    name: str
    resource: Resource
    description: str
    suggestion_id: str | None = None


@dataclass
class LearningTrackMetadata:
    """
    Metadata of a Learning Track.
    learning_track_id: Unique identifier for the learning track
    title: Title of the learning track
    is_draft: Indicates whether the learning track is a draft or published
    is_private: Indicates if the learning track is private
    career: Associated career for the learning track
    description: Description of the learning track
    thumbnail_image: URL to the thumbnail image of the learning track
    tags: List of tags related to the learning track
    createdBy: Creator of the Learning Track
    """

    learning_track_id: int
    title: str
    is_draft: bool
    is_private: bool
    career: str
    description: str
    thumbnail_image: str
    tags: list[str]
    createdBy: Creator
    career_path: str
    level: LevelEnum


@dataclass
class AllLearningTracks:
    """"
    Data of all Learning Tracks.
    learning_tracks: List of Learning Tracks
    hasResults: Indicates if the search has results
    """

    learning_tracks: list[LearningTrackMetadata]
    hasResults: bool


@dataclass
class ResourceProgress:
    """Data of a Resource Progress.

    Attributes:
        resource_id: Unique identifier for the resource
        completed: Indicates whether the resource has been completed
    """

    resource_id: str
    completed: bool


@dataclass
class UserProgress:
    """User progress for a learning track.

    Attributes:
        progress: List of learning tracks and their progress.

    """
    progress: list[ResourceProgress]
    learning_track_id: int | None = None


@dataclass
class LearningTrackCommit:
    """Data of a Learning Track Commit.

    Attributes:
        change_id: Unique identifier for the commit
        change_date: Date of the commit
        change_message: Message of the commit
    """

    change_id: str
    # short_id: str
    change_date: datetime.datetime
    # parent_ids: list
    # title: str
    change_message: str
    # author_name: str
    # author_email: str
    # authored_date: datetime.datetime
    # committer_name: str
    # committer_email: str
    # committed_date: datetime.datetime
    # trailers: dict
    # web_url: str

from aiohttp import ClientResponseError
from typing import Self
import traceback
from enum import Enum


class GitlabError(Exception):
    pass


class LookupErrors(Enum):
    learning_track = "learning_track"
    commit = "commit"


class GitlabLookupError(GitlabError):
    """LookupError

    Attributes:
        resource_type: The resource that doen't exist.
    """
    resource_type: LookupErrors

    def __init__(self, *args, resource_type: LookupErrors, **kwargs):
        super().__init__(*args, **kwargs)
        if resource_type is not None:
            self.resource_type = resource_type


class InvalidCredentialsError(ValueError, GitlabError):
    pass


class InvalidFileSizeError(ValueError, GitlabError):
    pass


class Unauthorized(GitlabError):
    pass


class EntityAlreadyExists(GitlabError):
    """An entity already exists.

    Attributes:
        entity: The entity that already exists.
    """

    entity: None | str = None
    """A string representing the entity that already exists."""

    def __init__(self, *args, entity: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        if entity is not None:
            self.entity = entity


class _ClientResponseBodyError(ClientResponseError):
    """A ClientResponseError with a json body.

    This class is used to wrap a ClientResponseError with a json body.
    """

    body: dict

    def __init__(self, *args, body: dict, **kwargs):  # pragma: no cover
        raise NotImplementedError(
            f"This class should not be instantiated "
            f"manually. Please use {self.__class__.__name__}.from_error() "
            f"instead."
        )

    @classmethod
    def from_error(
        cls,
        error: ClientResponseError,
        body: dict
    ) -> Self:
        """Create a _ClientResponseBodyError from a ClientResponseError.

        Args:
            error: The error to wrap.

        Returns:
            A _ClientResponseBodyError with the same attributes as the
            ClientResponseError.
        """
        newerror = cls.__new__(cls)
        newerror.__dict__ = error.__dict__.copy()

        if not __debug__:
            traceback.clear_frames(error.__traceback__)

        newerror.__cause__ = error
        newerror.add_note(f"Response body: {body}")
        newerror.body = body
        return newerror

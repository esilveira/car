from PIL import Image, UnidentifiedImageError
from io import BytesIO

from .exceptions import InvalidFileSizeError


class GitlabImage:
    @classmethod
    def _resize_image(cls, image: Image) -> Image:
        """Simple algorithm to resize image. Cut both dimensions in half.

        Args:
            image (Image): image to be resized

        Returns:
            Image: resized image
        """
        width, height = image.size
        image = image.resize((round(width/2), round(height/2)), Image.LANCZOS)
        return image

    @classmethod
    def resize_image(
        cls,
        image: Image,
        max_size: int
    ) -> bytes:
        """Resizes the image with a simple algorithm to send to gitlab

        Args:
            image (Image): image
            max_size (int): max size

        Returns:
            bytes: bytes to be sent to gitlab
        """
        _bytes = BytesIO()
        image.save(_bytes, 'jpeg')
        if len(_bytes.getvalue()) < max_size:
            return _bytes.getvalue()

        while True:
            _bytes = BytesIO()
            image = cls._resize_image(image)
            image.save(_bytes, 'jpeg')
            if len(_bytes.getvalue()) < max_size:
                break

        return _bytes.getvalue()

    @classmethod
    def get_image(
        cls,
        image_bytes: bytes | None,
        max_size: int,
        gitlab_max_size: int
    ) -> bytes:
        """_summary_

        Args:
            image_bytes (bytes): image as bytearray
            max_size (int): max size allowed by api
            gitlab_max_size (int): max size allowed by gitlab

        Raises:
            InvalidFileSizeError: File too big
            ValueError: Invalid image format

        Returns:
            bytes: image to send to gitlab
        """
        if not isinstance(image_bytes, (bytes, bytearray)):
            raise ValueError("Invalid image.")

        # Invalid image sent to Gitlab error. Maybe handle?
        # app.gitlab.exceptions._ClientResponseBodyError: 400, message='Bad Request',url=URL('http://127.0.0.1:80/api/v4/projects/8')  # noqa: E501
        #   | Response body: {'message': {'avatar': ['file format is not supported. Please try one of the following supported formats: image/png, image/jpeg, image/gif, image/bmp, image/tiff, image/vnd.microsoft.icon']}}  # # noqa: E501

        if len(image_bytes) > max_size:
            raise InvalidFileSizeError(
                "Invalid file size. Should be smaller than 3MB."
            )

        try:
            image = Image.open(BytesIO(image_bytes), formats=['jpeg'])
        except UnidentifiedImageError:
            # If image is in RGBA mode,
            # covert it to RBG to save as JPEG.
            # Works with PNG. May not work with others
            image = Image.open(BytesIO(image_bytes))
            image = image.convert('RGB')

        return cls.resize_image(image, gitlab_max_size)

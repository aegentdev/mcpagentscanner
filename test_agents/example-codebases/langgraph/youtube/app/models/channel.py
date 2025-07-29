"""Channel model for YouTube channels."""

from asgiref.sync import sync_to_async
from django.db import models
from django.db.models import Count

from app.models.video import Video


class Channel(models.Model):
    """A model representing a YouTube channel.

    This model stores information about YouTube channels including their
    unique identifier, name, profile image, description, and username.

    Attributes:
        id: A string representing the unique YouTube channel ID.
        name: A string representing the channel's display name.
        profile_image_url: A URL to the channel's profile image.
        description: A text field containing the channel's description.
        username: A string representing the channel's username.
    """

    id = models.CharField(max_length=100, primary_key=True)
    name = models.CharField(max_length=100)
    profile_image_url = models.URLField()
    description = models.TextField()
    username = models.CharField(max_length=100)
    url = models.URLField(default="")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    async def pretty_str(self):
        """Returns a pretty string representation of the channel."""
        # Create a thread-sensitive sync_to_async function
        get_video_count = sync_to_async(lambda: Video.objects.filter(channel=self).count(), thread_sensitive=True)

        # Execute the query
        count = await get_video_count()

        return f"""
        ID: {self.id}
        Name: {self.name}
        Username: {self.username}
        Description: {self.description}
        Scanned Videos Count: {count}
        """

    def pretty_str_sync(self):
        """Returns a pretty string representation of the channel (synchronous version).

        This method is used for background tasks where async operations might be problematic.
        """
        # Execute the query synchronously
        count = Video.objects.filter(channel=self).count()

        return f"""
        ID: {self.id}
        Name: {self.name}
        Username: {self.username}
        Description: {self.description}
        Scanned Videos Count: {count}
        """

    class Meta:
        """Metadata options for the Channel model."""

        verbose_name_plural = "Channels"

    def dict(self):
        """Converts the channel model instance to a dictionary.

        Returns:
            A dictionary containing the channel's attributes.
        """
        return {
            "id": self.id,
            "name": self.name,
            "profile_image_url": self.profile_image_url,
            "description": self.description,
            "username": self.username,
        }

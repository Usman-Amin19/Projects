from django.core.management.base import BaseCommand
from django.utils import timezone
from mainApp.models import ChatMessage


class Command(BaseCommand):
    help = 'Delete chat messages older than 7 days'

    def handle(self, *args, **options):
        # Run the cleanup
        ChatMessage.cleanup_old_messages()
        
        self.stdout.write(
            self.style.SUCCESS('Successfully cleaned up old chat messages')
        )

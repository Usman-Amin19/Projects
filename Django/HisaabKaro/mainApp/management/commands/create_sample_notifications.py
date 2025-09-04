from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from mainApp.models import Notification, Group


class Command(BaseCommand):
    help = 'Create sample notifications for testing'

    def handle(self, *args, **options):
        # Get a user to create notifications for
        try:
            user = User.objects.first()
            if not user:
                self.stdout.write(self.style.ERROR('No users found'))
                return
            
            # Create sample notifications
            Notification.objects.create(
                user=user,
                notification_type='expense_added',
                title='New expense added',
                message='John added a new expense "Dinner at restaurant" (PKR 500) in group Friends.'
            )
            
            Notification.objects.create(
                user=user,
                notification_type='settle_request',
                title='Settlement request received',
                message='Alice sent you a settlement request for PKR 250 in group Office Lunch.'
            )
            
            self.stdout.write(
                self.style.SUCCESS('Successfully created sample notifications')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating notifications: {e}')
            )

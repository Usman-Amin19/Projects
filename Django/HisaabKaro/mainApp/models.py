import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Category(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        verbose_name_plural = "Categories"
    
    def __str__(self):
        return self.name

class Group(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_groups')
    members = models.ManyToManyField(User, related_name='expense_groups')
    created_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    invite_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    
    def __str__(self):
        return self.name
    
    def get_balance_for_user(self, user):
        """Calculate how much user owes or is owed in this group"""
        from decimal import Decimal
        
        # Calculate using the detailed balance method for consistency
        detailed_balance = self.get_detailed_balance_for_user(user)
        
        # Sum up the detailed balance to get overall balance
        overall_balance = sum([
            balance_item['amount'] if balance_item['type'] == 'owed_to_you' 
            else -balance_item['amount'] 
            for balance_item in detailed_balance
        ], Decimal('0'))
        
        return overall_balance
    
    def get_detailed_balance_for_user(self, user):
        """Get detailed breakdown of who owes what to whom"""
        from collections import defaultdict
        from decimal import Decimal
        
        balances = defaultdict(lambda: Decimal('0'))
        
        # Get all unsettled expense splits for this user in this group
        user_splits = ExpenseSplit.objects.filter(
            expense__group=self,
            user=user,
            is_settled=False
        ).select_related('expense')
        
        for split in user_splits:
            # Calculate net amount: what user contributed minus what user owes
            net_amount = split.contribution - split.amount
            
            if net_amount != Decimal('0'):
                # If net_amount is positive: user overpaid, others owe user
                # If net_amount is negative: user underpaid, user owes others
                
                # Find who else participated in this expense
                other_splits = split.expense.splits.filter(is_settled=False).exclude(user=user)
                
                for other_split in other_splits:
                    other_net = other_split.contribution - other_split.amount
                    
                    # Only process if they have opposite net positions
                    if (net_amount > 0 and other_net < 0) or (net_amount < 0 and other_net > 0):
                        # Calculate how much should be transferred
                        transfer_amount = min(abs(net_amount), abs(other_net))
                        
                        if net_amount > 0:
                            # User overpaid, other underpaid -> other owes user
                            balances[other_split.user] -= transfer_amount
                        else:
                            # User underpaid, other overpaid -> user owes other
                            balances[other_split.user] += transfer_amount
                        
                        # Reduce the net amounts
                        if net_amount > 0:
                            net_amount -= transfer_amount
                        else:
                            net_amount += transfer_amount
                        
                        # Stop if user's net is now zero
                        if abs(net_amount) < Decimal('0.01'):
                            break
        
        # Convert to list of dictionaries with user details
        detailed_balances = []
        for other_user, amount in balances.items():
            if abs(amount) > Decimal('0.01'):  # Only show non-zero balances
                detailed_balances.append({
                    'user': other_user,
                    'amount': abs(amount),
                    'type': 'you_owe' if amount > Decimal('0') else 'owed_to_you'
                })
        
        return detailed_balances
    
    def has_pending_settlements_from_user(self, from_user):
        """Check if user has any pending settlement requests in this group"""
        return self.settlement_requests.filter(
            from_user=from_user, 
            status='pending'
        ).exists()
    
    def has_pending_settlement_to_user(self, from_user, to_user):
        """Check if there's a pending settlement from from_user to to_user"""
        return self.settlement_requests.filter(
            from_user=from_user,
            to_user=to_user,
            status='pending'
        ).exists()
    
    def get_invite_link(self):
        """Generate invite link for the group"""
        return f"/groups/join/{self.invite_token}/"

class GroupHistory(models.Model):
    ACTION_CHOICES = [
        ('created', 'Group Created'),
        ('member_added', 'Member Added'),
        ('member_removed', 'Member Removed'),
        ('expense_added', 'Expense Added'),
        ('expense_edited', 'Expense Edited'),
        ('expense_deleted', 'Expense Deleted'),
    ]
    
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='history')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    performed_by = models.ForeignKey(User, on_delete=models.CASCADE)
    target_user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='group_actions_received')
    description = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.group.name} - {self.action} by {self.performed_by.username}"

class PersonalExpense(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    description = models.TextField(blank=True)
    date = models.DateField(default=timezone.now)
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-date', '-created_at']
    
    def __str__(self):
        return f"{self.title} - PKR {self.amount}"

class GroupExpense(models.Model):
    SPLIT_CHOICES = [
        ('equal', 'Equal Split'),
        ('percentage', 'Split by Percentage'),
        ('amount', 'Split by Amount'),
    ]
    
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='expenses')
    title = models.CharField(max_length=200)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    description = models.TextField(blank=True)
    paid_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='paid_expenses')
    split_type = models.CharField(max_length=10, choices=SPLIT_CHOICES, default='equal')
    participants = models.ManyToManyField(User, related_name='participated_expenses')
    date = models.DateField(default=timezone.now)
    created_at = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_expenses')
    
    class Meta:
        ordering = ['-date', '-created_at']
    
    def __str__(self):
        return f"{self.title} - PKR {self.amount} (paid by {self.paid_by.username})"

class ExpenseSplit(models.Model):
    expense = models.ForeignKey(GroupExpense, on_delete=models.CASCADE, related_name='splits')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    percentage = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    contribution = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    is_settled = models.BooleanField(default=False)
    settled_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ['expense', 'user']
    
    def __str__(self):
        return f"{self.user.username} owes PKR {self.amount} for {self.expense.title}"

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    dark_mode = models.BooleanField(default=False)
    last_verification_email_sent = models.DateTimeField(null=True, blank=True)
    has_agreed_to_terms = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.user.username} Profile"

class ExpenseHistory(models.Model):
    ACTION_CHOICES = [
        ('created', 'Expense Created'),
        ('edited', 'Expense Edited'),
        ('amount_changed', 'Amount Changed'),
        ('participants_changed', 'Participants Changed'),
        ('split_type_changed', 'Split Type Changed'),
        ('description_changed', 'Description Changed'),
        ('title_changed', 'Title Changed'),
        ('category_changed', 'Category Changed'),
    ]
    
    expense = models.ForeignKey(GroupExpense, on_delete=models.CASCADE, related_name='history')
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    performed_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='expense_actions')
    timestamp = models.DateTimeField(default=timezone.now)
    old_value = models.TextField(null=True, blank=True)  # JSON field for old values
    new_value = models.TextField(null=True, blank=True)  # JSON field for new values
    description = models.TextField()
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.expense.title} - {self.get_action_display()} by {self.performed_by.username}"

class SettlementRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending Approval'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='settlement_requests')
    from_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_settlements')
    to_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_settlements')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    responded_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.from_user.username} → {self.to_user.username}: PKR {self.amount} ({self.status})"


class GroupMembership(models.Model):
    """Track when users joined groups for chat access control"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    joined_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        unique_together = ('user', 'group')
        ordering = ['-joined_at']
    
    def __str__(self):
        return f"{self.user.username} joined {self.group.name}"


class ChatMessage(models.Model):
    """Chat messages for groups"""
    MESSAGE_TYPES = [
        ('text', 'Text Message'),
        ('image', 'Image Message'),
    ]
    
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='chat_messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    message_type = models.CharField(max_length=10, choices=MESSAGE_TYPES, default='text')
    content = models.TextField(blank=True, help_text="Text content for text messages")  # For text messages
    image = models.ImageField(upload_to='chat_images/', blank=True, null=True)  # For image messages
    timestamp = models.DateTimeField(default=timezone.now)
    edited_at = models.DateTimeField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['timestamp']
    
    def __str__(self):
        if self.message_type == 'image':
            return f"{self.sender.get_full_name()} in {self.group.name}: [Image]"
        return f"{self.sender.get_full_name()} in {self.group.name}: {self.content[:50]}"
    
    def get_sender_name(self):
        return f"{self.sender.first_name} {self.sender.last_name}".strip() or self.sender.username
    
    def can_edit(self, user):
        """Check if user can edit this message"""
        return self.sender == user and not self.is_deleted
    
    def can_delete(self, user):
        """Check if user can delete this message"""
        return self.sender == user and not self.is_deleted
    
    def soft_delete(self):
        """Soft delete the message"""
        self.is_deleted = True
        self.content = ""
        if self.image:
            self.image.delete()
            self.image = None
        self.save()
    
    @classmethod
    def cleanup_old_messages(cls):
        """Delete messages older than 7 days"""
        cutoff_date = timezone.now() - timezone.timedelta(days=7)
        old_messages = cls.objects.filter(timestamp__lt=cutoff_date)
        
        # Delete associated images
        for message in old_messages:
            if message.image:
                message.image.delete()
        
        # Delete the messages
        old_messages.delete()


class ChatMessageRead(models.Model):
    """Track which messages have been read by which users"""
    message = models.ForeignKey(ChatMessage, on_delete=models.CASCADE, related_name='read_by')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    read_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        unique_together = ('message', 'user')
        ordering = ['-read_at']
    
    def __str__(self):
        return f"{self.user.username} read message {self.message.id}"


class Notification(models.Model):
    """System notifications for users"""
    NOTIFICATION_TYPES = [
        ('expense_added', 'Expense Added'),
        ('expense_edited', 'Expense Edited'),
        ('expense_deleted', 'Expense Deleted'),
        ('settle_request', 'Settlement Request'),
        ('settle_approved', 'Settlement Approved'),
        ('settle_rejected', 'Settlement Rejected'),
        ('group_invite', 'Group Invitation'),
        ('member_joined', 'Member Joined'),
        ('member_left', 'Member Left'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    
    # Related objects (optional, depends on notification type)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, blank=True)
    group_expense = models.ForeignKey('GroupExpense', on_delete=models.CASCADE, null=True, blank=True)
    personal_expense = models.ForeignKey('PersonalExpense', on_delete=models.CASCADE, null=True, blank=True)
    settlement = models.ForeignKey('SettlementRequest', on_delete=models.CASCADE, null=True, blank=True)
    
    # Additional data (JSON field for extra context)
    extra_data = models.JSONField(default=dict, blank=True)
    
    # Status
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    read_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_read']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.title}"
    
    def mark_as_read(self):
        """Mark notification as read"""
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])
    
    @classmethod
    def create_expense_notification(cls, expense, notification_type, actor_user):
        """Create notifications for expense-related actions"""
        # Get all group members except the actor
        recipients = expense.group.members.exclude(id=actor_user.id)
        
        # Only notify users who are involved in the expense
        if notification_type == 'expense_added':
            # Notify all group members except the one who added it
            pass
        elif notification_type in ['expense_edited', 'expense_deleted']:
            # Notify users who were involved in the expense splits
            split_users = expense.splits.values_list('user', flat=True)
            recipients = recipients.filter(id__in=split_users)
        
        type_labels = {
            'expense_added': 'added',
            'expense_edited': 'edited',
            'expense_deleted': 'deleted'
        }
        
        action = type_labels.get(notification_type, 'updated')
        title = f"Expense {action} in {expense.group.name}"
        message = f"{actor_user.get_full_name() or actor_user.username} {action} the expense '{expense.title}' (PKR {expense.amount}) in group {expense.group.name}."
        
        notifications = []
        for user in recipients:
            notifications.append(cls(
                user=user,
                notification_type=notification_type,
                title=title,
                message=message,
                group=expense.group,
                group_expense=expense,
                extra_data={
                    'actor': actor_user.username,
                    'amount': str(expense.amount)
                }
            ))
        
        cls.objects.bulk_create(notifications)
        return notifications
    
    @classmethod
    def create_settlement_notification(cls, settlement_request, notification_type):
        """Create notifications for settlement requests"""
        if notification_type == 'settle_request':
            # Notify the user who should pay
            title = f"Settlement request from {settlement_request.from_user.get_full_name() or settlement_request.from_user.username}"
            message = f"You have received a settlement request for PKR {settlement_request.amount} in group {settlement_request.group.name}."
            recipient = settlement_request.to_user
        elif notification_type == 'settle_approved':
            # Notify the user who sent the request
            title = "Settlement request approved"
            message = f"{settlement_request.to_user.get_full_name() or settlement_request.to_user.username} approved your settlement request for PKR {settlement_request.amount} in group {settlement_request.group.name}."
            recipient = settlement_request.from_user
        elif notification_type == 'settle_rejected':
            # Notify the user who sent the request
            title = "Settlement request rejected"
            message = f"{settlement_request.to_user.get_full_name() or settlement_request.to_user.username} rejected your settlement request for PKR {settlement_request.amount} in group {settlement_request.group.name}."
            recipient = settlement_request.from_user
        else:
            return None
        
        notification = cls.objects.create(
            user=recipient,
            notification_type=notification_type,
            title=title,
            message=message,
            group=settlement_request.group,
            settlement=settlement_request,
            extra_data={
                'amount': str(settlement_request.amount)
            }
        )
        return notification
    
    @classmethod
    def cleanup_old_notifications(cls):
        """Delete read notifications older than 30 days"""
        cutoff_date = timezone.now() - timezone.timedelta(days=30)
        cls.objects.filter(is_read=True, read_at__lt=cutoff_date).delete()

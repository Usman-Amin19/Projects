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
        # Amount user has paid
        paid_amount = sum([expense.amount for expense in self.expenses.filter(paid_by=user)])
        
        # Amount user owes
        owed_amount = sum([split.amount for split in ExpenseSplit.objects.filter(
            expense__group=self, user=user, is_settled=False
        )])
        
        return paid_amount - owed_amount
    
    def get_detailed_balance_for_user(self, user):
        """Get detailed breakdown of who owes what to whom"""
        user_debts = {}  # {other_user: amount_owed_to_them}
        user_credits = {}  # {other_user: amount_they_owe_user}
        
        # Get all expenses where user is involved
        for expense in self.expenses.all():
            if user == expense.paid_by:
                # User paid for this expense, others owe them
                for split in expense.splits.filter(is_settled=False):
                    if split.user != user:
                        if split.user not in user_credits:
                            user_credits[split.user] = 0
                        user_credits[split.user] += split.amount
            elif user in expense.participants.all():
                # User owes their share of this expense
                user_split = expense.splits.filter(user=user, is_settled=False).first()
                if user_split:
                    if expense.paid_by not in user_debts:
                        user_debts[expense.paid_by] = 0
                    user_debts[expense.paid_by] += user_split.amount
        
        # Net out debts and credits
        net_balances = {}
        all_users = set(user_debts.keys()) | set(user_credits.keys())
        
        for other_user in all_users:
            debt = user_debts.get(other_user, 0)
            credit = user_credits.get(other_user, 0)
            net = debt - credit
            
            if net > 0:
                net_balances[other_user] = {'amount': net, 'type': 'owes'}
            elif net < 0:
                net_balances[other_user] = {'amount': abs(net), 'type': 'owed_by'}
        
        return net_balances
    
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
        return f"{self.title} - ${self.amount}"

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
        return f"{self.title} - ${self.amount} (paid by {self.paid_by.username})"

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
        return f"{self.user.username} owes ${self.amount} for {self.expense.title}"

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
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='chat_messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    content = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    edited_at = models.DateTimeField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['timestamp']
    
    def __str__(self):
        return f"{self.sender.get_full_name()} in {self.group.name}: {self.content[:50]}"
    
    def get_sender_name(self):
        return f"{self.sender.first_name} {self.sender.last_name}".strip() or self.sender.username


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

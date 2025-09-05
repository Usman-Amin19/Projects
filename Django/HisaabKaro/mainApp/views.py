from django.shortcuts import render, get_object_or_404, redirect
from django.db.models import Sum, Count, Q
from django.contrib import messages
from django.http import JsonResponse
from decimal import Decimal
from datetime import datetime, date, timedelta
from django.template.defaultfilters import timesince
from .models import PersonalExpense, GroupExpense, Group, Category, ExpenseSplit, GroupHistory, UserProfile, ExpenseHistory, SettlementRequest, PaymentReminder, GroupDeletionRequest, GroupDeletionVote, ChatMessage, GroupMembership, ChatMessageRead, Notification
import logging

from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.urls import reverse
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils import timezone
from .decorators import user_not_authenticated, expense_step_required
from .forms import CustomUserRegistrationForm, CustomUserLoginForm, CustomPasswordResetForm, CustomSetPasswordForm, CustomChangePasswordForm

logger = logging.getLogger(__name__)

@user_not_authenticated
def register_page(request):
    if request.method == "POST":
        form = CustomUserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.username = form.cleaned_data['email']
            user.set_password(form.cleaned_data['password'])
            user.save()
            
            # Create user profile and set terms agreement
            user_profile, _ = UserProfile.objects.get_or_create(user=user)
            user_profile.has_agreed_to_terms = True
            
            # Save session theme preference to user profile
            session_dark_mode = request.session.get('dark_mode', False)
            user_profile.dark_mode = session_dark_mode
            user_profile.save()
            
            try:
                send_verification_email(request, user)
                messages.success(request, "A verification email has been sent to your email address.")
            except Exception:
                # If email fails, still show success but explain the issue
                messages.warning(request, "Account created but verification email could not be sent. Please contact support.")
            
            return redirect('mainApp:login')
        else:
            for field in form.errors:
                for error in form.errors[field]:
                    messages.error(request, error)
    else:
        form = CustomUserRegistrationForm()
    
    return render(request, "mainApp/register.html", {'form': form})


@user_not_authenticated
def login_page(request):
    cooldown_remaining = None
    show_resend = False
    
    if request.method == "POST":
        form = CustomUserLoginForm(request.POST)
        action = request.POST.get("action")
        email = request.POST.get("email", "").strip().lower()  # email field contains email
        
        if action == "resend_verification":
            cooldown_key = f"resend_cooldown_{email}"
            last_sent = request.session.get(cooldown_key)
            now = timezone.now().timestamp()
            if last_sent and now - last_sent < 300:
                cooldown_remaining = int(300 - (now - last_sent))
                messages.error(request, f"Please wait {cooldown_remaining//60}:{cooldown_remaining%60:02d} before resending.")
            else:
                try:
                    user = User.objects.get(email__iexact=email)
                    if not user.is_active:
                        send_verification_email(request, user)
                        request.session[cooldown_key] = now
                        cooldown_remaining = 300
                        messages.success(request, "Verification email resent! Please check your inbox.")
                        show_resend = True
                except User.DoesNotExist:
                    messages.error(request, "No account exists with this email.")
        elif form.is_valid():
            # Check if user has agreed to terms BEFORE logging in
            user_profile, created = UserProfile.objects.get_or_create(user=form.user)
            if not user_profile.has_agreed_to_terms:
                # Store user in session temporarily for terms agreement
                request.session['pending_login_user_id'] = form.user.id
                return redirect('mainApp:terms_agreement')
            
            # Save session theme preference to user profile if not already set
            if created or request.session.get('dark_mode') is not None:
                session_dark_mode = request.session.get('dark_mode', False)
                user_profile.dark_mode = session_dark_mode
                user_profile.save()
                # Clear session theme since it's now saved to user profile
                if 'dark_mode' in request.session:
                    del request.session['dark_mode']
            
            # User has agreed to terms, proceed with login
            login(request, form.user)
            return redirect('mainApp:home')
        else:
            try:
                user = User.objects.get(email__iexact=email)
                if not user.is_active:
                    show_resend = True
                    cooldown_key = f"resend_cooldown_{email}"
                    last_sent = request.session.get(cooldown_key)
                    now = timezone.now().timestamp()
                    if last_sent and now - last_sent < 300:
                        cooldown_remaining = int(300 - (now - last_sent))
            except User.DoesNotExist:
                pass
            for field in form.errors:
                for error in form.errors[field]:
                    messages.error(request, error)
    else:
        form = CustomUserLoginForm()
        cooldown_remaining = None
        show_resend = False
    
    storage = messages.get_messages(request)
    try:
        storage.used = True
    except Exception:
        pass
    return render(request, "mainApp/login.html", {"form": form, "cooldown_remaining": cooldown_remaining, "show_resend": show_resend})


@login_required
def logout_page(request):
    logout(request)
    return redirect('mainApp:login')


def verify_email(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (User.DoesNotExist, ValueError, TypeError):
        user = None
    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "✅ Email verified! You can now log in.")
    else:
        messages.error(request, "❌ Verification link is invalid or expired.")
    return redirect('mainApp:login')


def send_verification_email(request, user):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    verify_url = request.build_absolute_uri(
        reverse('mainApp:verify_email', kwargs={'uidb64': uid, 'token': token})
    )
    subject = 'Verify Your Email for HisaabKaro'
    message = f'''
Hi {user.first_name},

Thank you for registering! Please click the link below to verify your email address:

{verify_url}

If you did not create this account, you can safely ignore this email.

Thank you,
HisaabKaro Team
'''
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
        logger.info(f"Verification email sent successfully to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {str(e)}")
        messages.error(request, f"Failed to send verification email: {str(e)}. Please contact support if this continues.")
        raise e  # Re-raise to let calling function handle it

@user_not_authenticated
def password_reset(request):
    """Password reset view - handles email validation and sends reset email"""
    if request.method == "POST":
        form = CustomPasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email__iexact=email)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                reset_url = request.build_absolute_uri(
                    reverse('mainApp:password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
                )
                subject = 'Password Reset for HisaabKaro'
                message = f'''
Hi {user.first_name or user.username},

You requested a password reset for your HisaabKaro account.
Please click the link below to reset your password:

{reset_url}

If you did not request this, please ignore this email.
This link will expire in 24 hours.

Thank you,
HisaabKaro Team
'''
                try:
                    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
                    return redirect('mainApp:password_reset_done')
                except Exception as e:
                    logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
                    messages.error(request, "Failed to send reset email. Please try again later.")
            except User.DoesNotExist:
                # This shouldn't happen since the form already validates this
                messages.error(request, "User not found with this email address.")
        else:
            # Form validation failed, errors will be displayed in template
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, error)
    else:
        form = CustomPasswordResetForm()
    
    return render(request, 'mainApp/password_reset.html', {'form': form})

@user_not_authenticated
def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (User.DoesNotExist, ValueError, TypeError):
        user = None
    if user and default_token_generator.check_token(user, token):
        if request.method == "POST":
            reset_form = CustomSetPasswordForm(user=user, data=request.POST)
            if reset_form.is_valid():
                reset_form.save()
                messages.success(request, "Your password has been successfully reset.")
                return redirect('mainApp:password_reset_complete')
            else:
                for field, errors in reset_form.errors.items():
                    for error in errors:
                        messages.error(request, error)
                return render(request, "mainApp/password_reset_confirm.html", {
                    "form": reset_form,
                    "uidb64": uidb64,
                    "token": token
                })
        else:
            reset_form = CustomSetPasswordForm(user=user)
            return render(request, "mainApp/password_reset_confirm.html", {
                "form": reset_form,
                "uidb64": uidb64,
                "token": token
            })
    else:
        messages.error(request, "The password reset link is invalid or has expired.")
        return redirect('mainApp:login')

@user_not_authenticated
def password_reset_done(request):
    """Password reset email sent confirmation page"""
    return render(request, 'mainApp/password_reset_done.html')

@user_not_authenticated
def password_reset_complete(request):
    """Password reset complete confirmation page"""
    return render(request, 'mainApp/password_reset_complete.html')

@login_required
def profile_page(request):
    """View for the user's profile page (read-only display)"""
    context = {
        'user': request.user,
    }
    return render(request, 'mainApp/profile.html', context)

@login_required
def edit_profile(request):
    """View for editing user profile"""
    if request.method == 'POST':
        # Update profile information
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        
        # Validation
        if not first_name:
            messages.error(request, "First name is required.")
            return render(request, 'mainApp/edit_profile.html', {'user': request.user})
        
        if len(first_name) > 30:
            messages.error(request, "First name must be 30 characters or less.")
            return render(request, 'mainApp/edit_profile.html', {'user': request.user})
            
        if len(last_name) > 30:
            messages.error(request, "Last name must be 30 characters or less.")
            return render(request, 'mainApp/edit_profile.html', {'user': request.user})
            
        
        # Update user information
        request.user.first_name = first_name
        request.user.last_name = last_name
        request.user.save()
        
        messages.success(request, "Profile updated successfully!")
        return redirect('mainApp:profile')
    
    # GET request
    context = {
        'user': request.user,
    }
    return render(request, 'mainApp/edit_profile.html', context)

@login_required
def change_password(request):
    """View for changing user password using CustomChangePasswordForm"""
    if request.method == 'POST':
        form = CustomChangePasswordForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            
            # Update session to keep user logged in
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(request, request.user)
            
            messages.success(request, "Password changed successfully!")
            return redirect('mainApp:profile')
    else:
        form = CustomChangePasswordForm(user=request.user)
    
    return render(request, 'mainApp/change_password.html', {'form': form})

@login_required
def check_pending_dues(request):
    """AJAX view to check if user has pending dues before account deletion"""
    from django.http import JsonResponse
    from decimal import Decimal
    
    try:
        pending_groups = []
        
        # Check all groups where user is a member
        user_memberships = GroupMembership.objects.filter(user=request.user)
        
        for membership in user_memberships:
            group = membership.group
            
            # Calculate user's balance in this group
            user_balance = Decimal('0.00')
            
            # Get all expenses where this user is involved
            expenses = GroupExpense.objects.filter(group=group)
            
            for expense in expenses:
                # Check if user paid for this expense
                if expense.paid_by == request.user:
                    user_balance += expense.amount
                
                # Check if user owes money for this expense
                splits = ExpenseSplit.objects.filter(expense=expense, user=request.user)
                for split in splits:
                    user_balance -= split.amount
            
            # If balance is not zero, user has pending dues
            if abs(user_balance) > Decimal('0.01'):  # Allow for small rounding errors
                if user_balance > 0:
                    pending_groups.append(f"{group.name} (You are owed PKR {user_balance:.2f})")
                else:
                    pending_groups.append(f"{group.name} (You owe PKR {abs(user_balance):.2f})")
        
        return JsonResponse({
            'has_pending_dues': len(pending_groups) > 0,
            'pending_groups': pending_groups
        })
        
    except Exception as e:
        return JsonResponse({
            'error': 'Error checking pending dues',
            'has_pending_dues': True,  # Err on the side of caution
            'pending_groups': []
        }, status=500)

@login_required
def delete_account(request):
    """AJAX view to delete user account after checking for pending dues"""
    from django.http import JsonResponse
    from decimal import Decimal
    
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)
    
    try:
        # Double-check for pending dues
        user_memberships = GroupMembership.objects.filter(user=request.user)
        has_pending_dues = False
        
        for membership in user_memberships:
            group = membership.group
            user_balance = Decimal('0.00')
            
            expenses = GroupExpense.objects.filter(group=group)
            for expense in expenses:
                if expense.paid_by == request.user:
                    user_balance += expense.amount
                
                splits = ExpenseSplit.objects.filter(expense=expense, user=request.user)
                for split in splits:
                    user_balance -= split.amount
            
            if abs(user_balance) > Decimal('0.01'):
                has_pending_dues = True
                break
        
        if has_pending_dues:
            return JsonResponse({
                'success': False,
                'error': 'Cannot delete account with pending dues. Please settle all balances first.'
            })
        
        # Check if user is admin of any groups with other members
        admin_groups = Group.objects.filter(created_by=request.user)
        for group in admin_groups:
            member_count = GroupMembership.objects.filter(group=group).count()
            if member_count > 1:  # More than just the admin
                return JsonResponse({
                    'success': False,
                    'error': f'Cannot delete account. You are admin of group "{group.name}" which has other members. Please transfer admin rights or ensure all members leave the group first.'
                })
        
        # If we get here, it's safe to delete the account
        user_email = request.user.email
        
        # Delete user account (this will cascade delete related objects)
        request.user.delete()
        
        # Log the deletion
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"User account deleted: {user_email}")
        
        return JsonResponse({
            'success': True,
            'message': 'Account deleted successfully'
        })
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error deleting account for user {request.user.email}: {str(e)}")
        
        return JsonResponse({
            'success': False,
            'error': 'An error occurred while deleting your account. Please try again or contact support.'
        }, status=500)

def home(request):
    context = {}
    
    # If user is authenticated, get some stats
    if request.user.is_authenticated:
        # Personal expense stats
        personal_expenses = PersonalExpense.objects.filter(user=request.user)
        personal_total = personal_expenses.aggregate(total=Sum('amount'))['total'] or 0
        personal_count = personal_expenses.count()
        
        # Group expense stats
        user_groups = Group.objects.filter(members=request.user, is_active=True)
        group_count = user_groups.count()
        
        # Recent group expenses where user is involved
        recent_group_expenses = GroupExpense.objects.filter(
            group__members=request.user
        ).select_related('group', 'paid_by')[:5]
        
        context.update({
            'personal_total': personal_total,
            'personal_count': personal_count,
            'group_count': group_count,
            'recent_group_expenses': recent_group_expenses,
            'user_groups': user_groups,
        })
    
    return render(request, 'mainApp/home.html', context)

@login_required
def groups(request):
    """View for listing all groups"""
    from decimal import Decimal
    
    user_groups = Group.objects.filter(members=request.user, is_active=True)
    
    group_data = []
    for group in user_groups:
        balance = group.get_balance_for_user(request.user)
        group_data.append({
            'group': group,
            'balance': balance,
            'you_owe': balance < Decimal('0'),
            'you_are_owed': balance > Decimal('0'),
        })
    
    return render(request, 'mainApp/groups.html', {'group_data': group_data})

@login_required
def group_detail(request, group_id):
    """View for showing group details and expenses"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    expenses = GroupExpense.objects.filter(group=group)
    
    # Calculate user's balance in this group
    balance = group.get_balance_for_user(request.user)
    detailed_balance = group.get_detailed_balance_for_user(request.user)
    
    # Calculate overall balance from detailed balance
    from decimal import Decimal
    overall_balance = sum([
        balance_item['amount'] if balance_item['type'] == 'owed_to_you' 
        else -balance_item['amount'] 
        for balance_item in detailed_balance
    ], Decimal('0'))  # Start with Decimal('0') instead of 0
    
    # Check for pending settlements
    has_pending_settlements = group.has_pending_settlements_from_user(request.user)
    
    # Get pending settlement requests for this user
    pending_settlements_to_approve = SettlementRequest.objects.filter(
        group=group, 
        to_user=request.user, 
        status='pending'
    )
    
    # Get group history
    history = GroupHistory.objects.filter(group=group)[:10]  # Last 10 actions
    
    # Check for pending group deletion request
    pending_deletion_request = None
    deletion_votes = []
    user_deletion_vote = None
    
    try:
        pending_deletion_request = GroupDeletionRequest.objects.get(
            group=group,
            status='pending'
        )
        deletion_votes = GroupDeletionVote.objects.filter(
            deletion_request=pending_deletion_request
        ).order_by('voted_at')
        user_deletion_vote = GroupDeletionVote.objects.get(
            deletion_request=pending_deletion_request,
            user=request.user
        )
    except GroupDeletionRequest.DoesNotExist:
        pass
    except GroupDeletionVote.DoesNotExist:
        pass
    
    context = {
        'group': group,
        'expenses': expenses,
        'balance': balance,
        'detailed_balance': detailed_balance,
        'overall_balance': overall_balance,
        'you_owe': overall_balance < Decimal('0'),
        'you_are_owed': overall_balance > Decimal('0'),
        'has_pending_settlements': has_pending_settlements,
        'pending_settlements': pending_settlements_to_approve,
        'history': history,
        'user': request.user,
        'pending_deletion_request': pending_deletion_request,
        'deletion_votes': deletion_votes,
        'user_deletion_vote': user_deletion_vote,
    }
    return render(request, 'mainApp/group_detail.html', context)

@login_required
def expense_detail(request, group_id, expense_id):
    """View for showing detailed expense information"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    expense = get_object_or_404(GroupExpense, id=expense_id, group=group)
    
    # Check if user is a participant of this expense
    if request.user not in expense.participants.all():
        messages.error(request, "You can only view expenses you participated in.")
        return redirect('mainApp:group_detail', group_id=group.id)
    
    # Calculate total contributions
    from decimal import Decimal
    total_contributions = sum([split.contribution for split in expense.splits.all()], Decimal('0'))
    
    # Calculate net balances for each split
    splits_with_net = []
    for split in expense.splits.all():
        net_balance = split.contribution - split.amount
        splits_with_net.append({
            'split': split,
            'net_balance': net_balance,
            'net_positive': net_balance > 0,
            'net_negative': net_balance < 0,
            'net_zero': abs(net_balance) < Decimal('0.01')
        })
    
    # Calculate per-person amount for equal splits
    per_person_amount = None
    if expense.split_type == 'equal' and expense.participants.count() > 0:
        per_person_amount = expense.amount / expense.participants.count()
    
    # Get expense history
    history = expense.history.all().order_by('-timestamp')[:10]  # Show last 10 history entries
    
    context = {
        'group': group,
        'expense': expense,
        'total_contributions': total_contributions,
        'splits_with_net': splits_with_net,
        'per_person_amount': per_person_amount,
        'history': history,
    }
    return render(request, 'mainApp/expense_detail.html', context)

@login_required
def create_group(request):
    """View for creating a new group"""
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        
        if name:
            group = Group.objects.create(
                name=name,
                description=description,
                created_by=request.user
            )
            group.members.add(request.user)
            
            # Create history entry
            GroupHistory.objects.create(
                group=group,
                action='created',
                performed_by=request.user,
                description=f"Group '{name}' was created"
            )
            
            messages.success(request, f"Group '{name}' created successfully!")
            return redirect('mainApp:group_detail', group_id=group.id)
    
    return render(request, 'mainApp/create_group.html')

@login_required
def add_personal_expense(request):
    """View for adding personal expense"""
    if request.method == 'POST':
        title = request.POST.get('title')
        amount = request.POST.get('amount')
        description = request.POST.get('description', '')
        category_id = request.POST.get('category')
        new_category_name = request.POST.get('new_category_name', '').strip()
        
        user = request.user
        
        # Handle new category creation
        category = None
        if new_category_name and not category_id:
            # Check if category already exists
            existing_category = Category.objects.filter(name__iexact=new_category_name).first()
            if existing_category:
                category = existing_category
            else:
                # Create new category
                category = Category.objects.create(name=new_category_name)
                messages.success(request, f"New category '{new_category_name}' created successfully!")
        elif category_id:
            category = Category.objects.get(id=category_id)
        
        expense = PersonalExpense.objects.create(
            user=user,
            title=title,
            amount=Decimal(amount),
            description=description,
            category=category
        )
        
        messages.success(request, f"Personal expense '{title}' added successfully!")
        return redirect('mainApp:personal_expenses')
    
    categories = Category.objects.all()
    return render(request, 'mainApp/add_personal_expense.html', {'categories': categories})

@login_required
def join_group(request, invite_token):
    """View for joining a group via invite link"""
    try:
        group = Group.objects.get(invite_token=invite_token, is_active=True)
    except Group.DoesNotExist:
        messages.error(request, "Invalid or expired invite link.")
        return redirect('mainApp:groups')
    
    user = request.user
    
    if request.method == 'POST':
        if user not in group.members.all():
            group.members.add(user)
            
            # Create history entry
            GroupHistory.objects.create(
                group=group,
                action='member_added',
                performed_by=user,
                target_user=user,
                description=f"{user.first_name} {user.last_name} joined the group via invite link"
            )
            
            messages.success(request, f"You have successfully joined '{group.name}'!")
        else:
            messages.info(request, f"You are already a member of '{group.name}'.")
        
        return redirect('mainApp:group_detail', group_id=group.id)
    
    # Calculate total spent in the group
    total_spent = sum([expense.amount for expense in group.expenses.all()]) if group.expenses.exists() else 0
    already_member = user in group.members.all()
    
    context = {
        'group': group,
        'already_member': already_member,
        'total_spent': total_spent,
    }
    return render(request, 'mainApp/join_group.html', context)

@login_required
def join_group_form(request):
    """View for manual group joining using invite link"""
    if request.method == 'POST':
        invite_link = request.POST.get('invite_link', '').strip()
        
        # Extract token from the link
        try:
            # Handle both full URL and just the token
            if '/groups/join/' in invite_link:
                invite_token = invite_link.split('/groups/join/')[-1].rstrip('/')
            else:
                # Assume it's just the token
                invite_token = invite_link
            
            # Validate token format (UUID)
            import uuid
            uuid.UUID(invite_token)
            
            # Redirect to the existing join_group view
            return redirect('mainApp:join_group', invite_token=invite_token)
            
        except (ValueError, IndexError):
            messages.error(request, "Invalid invite link format. Please check and try again.")
    
    return render(request, 'mainApp/join_group_form.html')

@login_required
def personal_expenses(request):
    """View for managing personal expenses"""
    expenses = PersonalExpense.objects.filter(user=request.user)
    categories = Category.objects.all()
    return render(request, 'mainApp/personal_expenses.html', {
        'expenses': expenses,
        'categories': categories
    })

def toggle_theme(request):
    """Toggle theme preference for both authenticated and non-authenticated users"""
    if request.method == 'POST':
        if request.user.is_authenticated:
            # For authenticated users, save to UserProfile
            profile, created = UserProfile.objects.get_or_create(user=request.user)
            profile.dark_mode = not profile.dark_mode
            profile.save()
            return JsonResponse({'success': True, 'dark_mode': profile.dark_mode})
        else:
            # For non-authenticated users, save to session
            current_mode = request.session.get('dark_mode', False)
            new_mode = not current_mode
            request.session['dark_mode'] = new_mode
            return JsonResponse({'success': True, 'dark_mode': new_mode})
    return JsonResponse({'success': False})

def terms_of_use(request):
    """Terms of Use page"""
    return render(request, 'mainApp/terms_of_use.html')

def privacy_policy(request):
    """Privacy Policy page"""
    return render(request, 'mainApp/privacy_policy.html')

@login_required
def terms_agreement(request):
    """Terms agreement page for users who haven't agreed yet"""
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'agree':
            profile.has_agreed_to_terms = True
            profile.save()
            messages.success(request, 'Thank you for agreeing to our terms!')
            return redirect('mainApp:home')
        elif action == 'disagree':
            logout(request)
            messages.info(request, 'You must agree to our terms to use the service.')
            return redirect('mainApp:login')
    
    return render(request, 'mainApp/terms_agreement.html')

@login_required
def delete_group_expense(request, group_id, expense_id):
    """Delete a group expense"""
    if request.method == 'POST':
        group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
        expense = get_object_or_404(GroupExpense, id=expense_id, group=group)
        
        # Check if user is a participant of this expense
        if request.user not in expense.participants.all():
            return JsonResponse({'success': False, 'error': 'You can only delete expenses you participated in.'})
        
        # Record in group history
        GroupHistory.objects.create(
            group=group,
            action='expense_deleted',
            performed_by=request.user,
            description=f"Expense '{expense.title}' (PKR {expense.amount}) was deleted"
        )
        
        # Create notifications for group members before deleting
        try:
            notifications = Notification.create_expense_notification(expense, 'expense_deleted', request.user)
            # Send real-time updates
            for notification in notifications:
                send_notification_update(notification.user)
        except Exception as e:
            print(f"Error creating notifications: {e}")
        
        # Delete the expense (this will cascade to splits and history)
        expense_title = expense.title
        expense_amount = expense.amount
        expense.delete()
        
        return JsonResponse({'success': True, 'message': f"Expense '{expense_title}' deleted successfully."})
    
    return JsonResponse({'success': False, 'error': 'Invalid request method.'})

@login_required
def expense_history(request, group_id, expense_id):
    """Get the history of changes for an expense"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    expense = get_object_or_404(GroupExpense, id=expense_id, group=group)
    
    # Check if user is a participant of this expense
    if request.user not in expense.participants.all():
        return JsonResponse({'success': False, 'error': 'You can only view history of expenses you participated in.'})
    
    # Get expense history
    history_entries = expense.history.all()
    
    history_data = []
    for entry in history_entries:
        history_data.append({
            'date': entry.timestamp.strftime('%Y-%m-%d %H:%M'),
            'action': entry.get_action_display(),
            'user': f"{entry.performed_by.first_name} {entry.performed_by.last_name}",
            'details': entry.description
        })
    
    return JsonResponse({
        'success': True,
        'history': history_data
    })


# ============== NEW STEP-BASED VIEWS ==============

# Redirect views for legacy URLs
@login_required
def add_group_expense_redirect(request, group_id):
    """Redirect legacy add expense URL to step 1"""
    return redirect('mainApp:add_group_expense_step1', group_id=group_id)

@login_required
def edit_group_expense_redirect(request, group_id, expense_id):
    """Redirect legacy edit expense URL to step 1"""
    return redirect('mainApp:edit_group_expense_step1', group_id=group_id, expense_id=expense_id)

# Helper function to clear session data
def clear_expense_session(request, session_key='expense_data'):
    """Clear expense session data"""
    if session_key in request.session:
        del request.session[session_key]
        request.session.modified = True

# Helper function to get expense data from session
def get_expense_session_data(request, session_key='expense_data'):
    """Get expense data from session with validation"""
    return request.session.get(session_key, {})

# ============== ADD EXPENSE STEP VIEWS ==============

@login_required
def add_group_expense_step1(request, group_id):
    """Step 1: Basic expense details"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    
    # Clear any existing expense session data to start fresh
    clear_expense_session(request)
    
    # Check if group has at least 2 members
    if group.members.count() < 2:
        messages.error(request, "You need at least 2 members in the group to add expenses.")
        return redirect('mainApp:group_detail', group_id=group.id)
    
    if request.method == 'POST':
        title = request.POST.get('title')
        amount = request.POST.get('amount')
        description = request.POST.get('description', '')
        category_id = request.POST.get('category')
        new_category_name = request.POST.get('new_category_name', '').strip()
        
        # Handle new category creation
        if new_category_name and not category_id:
            existing_category = Category.objects.filter(name__iexact=new_category_name).first()
            if existing_category:
                category_id = str(existing_category.id)
            else:
                new_category = Category.objects.create(name=new_category_name)
                category_id = str(new_category.id)
                messages.success(request, f"New category '{new_category_name}' created successfully!")
        
        # Store in session for next steps
        expense_data = {
            'title': title,
            'amount': amount,
            'description': description,
            'category_id': category_id,
            'step_1_completed': True,
            'group_id': group_id,
        }
        request.session['expense_data'] = expense_data
        request.session.modified = True
        
        messages.success(request, "Basic details saved! Now select participants.")
        return redirect('mainApp:add_group_expense_step2', group_id=group_id)
    
    # GET request - show form with any existing data
    expense_data = get_expense_session_data(request)
    
    context = {
        'group': group,
        'categories': Category.objects.all(),
        'step': 1,
        'expense_data': expense_data,
        'is_editing': False,
    }
    return render(request, 'mainApp/group_expense_step1.html', context)

@login_required
@expense_step_required([1])
def add_group_expense_step2(request, group_id):
    """Step 2: Select participants"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    expense_data = get_expense_session_data(request)
    
    if request.method == 'POST':
        participant_ids = request.POST.getlist('participants')
        
        # Automatically include the current user
        current_user_id = str(request.user.id)
        if current_user_id not in participant_ids:
            participant_ids.append(current_user_id)
        
        # Validate that at least 2 participants are selected
        if len(participant_ids) < 2:
            messages.error(request, "You need at least 1 more participant besides yourself.")
            context = {
                'group': group,
                'step': 2,
                'expense_data': expense_data,
                'error': True,
                'is_editing': False,
            }
            return render(request, 'mainApp/group_expense_step2.html', context)
        
        # Update session data
        expense_data.update({
            'participant_ids': participant_ids,
            'step_2_completed': True,
        })
        request.session['expense_data'] = expense_data
        request.session.modified = True
        
        messages.success(request, "Participants selected! Now set contributions.")
        return redirect('mainApp:add_group_expense_step3', group_id=group_id)
    
    # GET request
    context = {
        'group': group,
        'step': 2,
        'expense_data': expense_data,
        'is_editing': False,
    }
    return render(request, 'mainApp/group_expense_step2.html', context)

@login_required
@expense_step_required([1, 2])
def add_group_expense_step3(request, group_id):
    """Step 3: Set contributions"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    expense_data = get_expense_session_data(request)
    
    participant_ids = expense_data.get('participant_ids', [])
    participants = User.objects.filter(id__in=participant_ids)
    
    if request.method == 'POST':
        contributions = {}
        
        for participant_id in participant_ids:
            contribution = request.POST.get(f'contribution_{participant_id}', '0.0')
            contributions[participant_id] = str(contribution)  # Store as string for JSON
        
        # Update session data
        expense_data.update({
            'contributions': contributions,
            'step_3_completed': True,
        })
        request.session['expense_data'] = expense_data
        request.session.modified = True
        
        messages.success(request, "Contributions set! Now choose how to split the expense.")
        return redirect('mainApp:add_group_expense_step4', group_id=group_id)
    
    # GET request
    context = {
        'group': group,
        'participants': participants,
        'step': 3,
        'expense_data': expense_data,
        'is_editing': False,
    }
    return render(request, 'mainApp/group_expense_step3.html', context)

@login_required
@expense_step_required([1, 2, 3])
def add_group_expense_step4(request, group_id):
    """Step 4: Choose split type and finalize"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    expense_data = get_expense_session_data(request)
    
    participant_ids = expense_data.get('participant_ids', [])
    participants = User.objects.filter(id__in=participant_ids)
    
    if request.method == 'POST':
        split_type = request.POST.get('split_type')
        
        # Create the expense
        category = None
        if expense_data.get('category_id'):
            category = Category.objects.get(id=expense_data['category_id'])
        
        expense = GroupExpense.objects.create(
            group=group,
            title=expense_data['title'],
            amount=Decimal(expense_data['amount']),
            description=expense_data['description'],
            category=category,
            paid_by=request.user,
            created_by=request.user,
            split_type=split_type
        )
        
        # Add participants
        participant_ids = [int(pid) for pid in participant_ids]
        for participant in participants:
            expense.participants.add(participant)
        
        # Create splits based on split type
        total_amount = Decimal(expense_data['amount'])
        contributions = {k: Decimal(v) for k, v in expense_data.get('contributions', {}).items()}
        
        if split_type == 'equal':
            split_amount = total_amount / len(participant_ids)
            for participant_id in participant_ids:
                participant = User.objects.get(id=participant_id)
                ExpenseSplit.objects.create(
                    expense=expense,
                    user=participant,
                    amount=split_amount,
                    contribution=contributions.get(str(participant_id), Decimal('0.0'))
                )
        elif split_type == 'percentage':
            for participant_id in participant_ids:
                percentage = Decimal(request.POST.get(f'percentage_{participant_id}', '0'))
                split_amount = (total_amount * percentage) / 100
                participant = User.objects.get(id=participant_id)
                ExpenseSplit.objects.create(
                    expense=expense,
                    user=participant,
                    amount=split_amount,
                    percentage=percentage,
                    contribution=contributions.get(str(participant_id), Decimal('0.0'))
                )
        elif split_type == 'amount':
            for participant_id in participant_ids:
                split_amount = Decimal(request.POST.get(f'amount_{participant_id}', '0'))
                participant = User.objects.get(id=participant_id)
                ExpenseSplit.objects.create(
                    expense=expense,
                    user=participant,
                    amount=split_amount,
                    contribution=contributions.get(str(participant_id), Decimal('0.0'))
                )
        
        # Create history entries
        ExpenseHistory.objects.create(
            expense=expense,
            action='created',
            performed_by=request.user,
            description=f"Expense created with amount PKR{expense.amount}"
        )
        
        GroupHistory.objects.create(
            group=group,
            action='expense_added',
            performed_by=request.user,
            description=f"Expense '{expense.title}' was added for PKR{expense.amount}"
        )
        
        # Create notifications for group members
        try:
            notifications = Notification.create_expense_notification(expense, 'expense_added', request.user)
            # Send real-time updates
            for notification in notifications:
                send_notification_update(notification.user)
        except Exception as e:
            print(f"Error creating notifications: {e}")
        
        # Clear session data
        clear_expense_session(request)
        
        messages.success(request, f"Expense '{expense.title}' added successfully!")
        return redirect('mainApp:group_detail', group_id=group.id)
    
    # GET request
    context = {
        'group': group,
        'participants': participants,
        'step': 4,
        'expense_data': expense_data,
        'is_editing': False,
    }
    return render(request, 'mainApp/group_expense_step4.html', context)

# ============== EDIT EXPENSE STEP VIEWS ==============

@login_required
def edit_group_expense_step1(request, group_id, expense_id):
    """Step 1: Edit basic expense details"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    expense = get_object_or_404(GroupExpense, id=expense_id, group=group)
    
    # Clear any existing session data when starting fresh edit
    if 'expense_data' in request.session:
        del request.session['expense_data']
        request.session.modified = True
    
    # Check if user is a participant
    if request.user not in expense.participants.all():
        messages.error(request, "You can only edit expenses you participated in.")
        return redirect('mainApp:group_detail', group_id=group.id)
    
    if request.method == 'POST':
        title = request.POST.get('title')
        amount = request.POST.get('amount')
        description = request.POST.get('description', '')
        category_id = request.POST.get('category')
        new_category_name = request.POST.get('new_category_name', '').strip()
        
        # Handle new category creation
        if new_category_name and not category_id:
            existing_category = Category.objects.filter(name__iexact=new_category_name).first()
            if existing_category:
                category_id = str(existing_category.id)
            else:
                new_category = Category.objects.create(name=new_category_name)
                category_id = str(new_category.id)
                messages.success(request, f"New category '{new_category_name}' created successfully!")
        
        # Get existing session data to check for changes
        existing_expense_data = get_expense_session_data(request) or {}
        existing_amount = existing_expense_data.get('amount', str(expense.amount))
        
        # Store in session for next steps
        expense_data = {
            'title': title,
            'amount': amount,
            'description': description,
            'category_id': category_id,
            'step_1_completed': True,
            'group_id': group_id,
            'expense_id': expense_id,
            'original_participants': list(expense.participants.values_list('id', flat=True)),
            'is_editing': True,
        }
        
        # If amount changed, clear downstream data that depends on amount
        if str(amount) != str(existing_amount):
            existing_expense_data.pop('contributions', None)
            existing_expense_data.pop('step_3_completed', None)
            existing_expense_data.pop('step_4_completed', None)
            messages.info(request, "Amount updated. Please review contributions and splits again.")
        
        # Preserve other existing data and update with new data
        existing_expense_data.update(expense_data)
        request.session['expense_data'] = existing_expense_data
        request.session.modified = True
        
        messages.success(request, "Basic details updated! Now review participants.")
        return redirect('mainApp:edit_group_expense_step2', group_id=group_id, expense_id=expense_id)
    
    # GET request - pre-fill with existing data
    expense_data = get_expense_session_data(request)
    if not expense_data:
        expense_data = {
            'title': expense.title,
            'amount': str(expense.amount),
            'description': expense.description,
            'category_id': expense.category.id if expense.category else None,
        }
    
    context = {
        'group': group,
        'expense': expense,
        'categories': Category.objects.all(),
        'step': 1,
        'expense_data': expense_data,
        'is_editing': True,
    }
    return render(request, 'mainApp/group_expense_step1.html', context)

@login_required
@expense_step_required([1])
def edit_group_expense_step2(request, group_id, expense_id):
    """Step 2: Edit participants"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    expense = get_object_or_404(GroupExpense, id=expense_id, group=group)
    expense_data = get_expense_session_data(request)
    
    if request.method == 'POST':
        participant_ids = request.POST.getlist('participants')
        
        # Automatically include the current user
        current_user_id = str(request.user.id)
        if current_user_id not in participant_ids:
            participant_ids.append(current_user_id)
        
        # Validate that at least 2 participants are selected
        if len(participant_ids) < 2:
            messages.error(request, "You need at least 1 more participant besides yourself.")
            context = {
                'group': group,
                'expense': expense,
                'step': 2,
                'expense_data': expense_data,
                'error': True,
                'is_editing': True,
            }
            return render(request, 'mainApp/group_expense_step2.html', context)
        
        # Check if participants have changed
        previous_participants = set(expense_data.get('participant_ids', []))
        new_participants = set(participant_ids)
        
        # Update session data
        expense_data.update({
            'participant_ids': participant_ids,
            'step_2_completed': True,
        })
        
        # If participants changed, clear the contributions and splits data
        if previous_participants != new_participants:
            expense_data.pop('contributions', None)
            expense_data.pop('step_3_completed', None)
            expense_data.pop('step_4_completed', None)
            messages.info(request, "Participants updated. Please review contributions and splits again.")
        
        request.session['expense_data'] = expense_data
        request.session.modified = True
        
        messages.success(request, "Participants updated! Now review contributions.")
        return redirect('mainApp:edit_group_expense_step3', group_id=group_id, expense_id=expense_id)
    
    # GET request - pre-fill with existing participants
    if not expense_data.get('participant_ids'):
        expense_data['participant_ids'] = [str(p.id) for p in expense.participants.all()]
    
    context = {
        'group': group,
        'expense': expense,
        'step': 2,
        'expense_data': expense_data,
        'is_editing': True,
    }
    return render(request, 'mainApp/group_expense_step2.html', context)

@login_required
@expense_step_required([1, 2])
def edit_group_expense_step3(request, group_id, expense_id):
    """Step 3: Edit contributions"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    expense = get_object_or_404(GroupExpense, id=expense_id, group=group)
    expense_data = get_expense_session_data(request)
    
    participant_ids = expense_data.get('participant_ids', [])
    participants = User.objects.filter(id__in=participant_ids)
    
    if request.method == 'POST':
        contributions = {}
        
        for participant_id in participant_ids:
            contribution = request.POST.get(f'contribution_{participant_id}', '0.0')
            contributions[participant_id] = str(contribution)
        
        # Update session data
        expense_data.update({
            'contributions': contributions,
            'step_3_completed': True,
        })
        request.session['expense_data'] = expense_data
        request.session.modified = True
        
        messages.success(request, "Contributions updated! Now finalize the split.")
        return redirect('mainApp:edit_group_expense_step4', group_id=group_id, expense_id=expense_id)
    
    # GET request - pre-fill with existing contributions
    if not expense_data.get('contributions'):
        contributions = {}
        for split in expense.splits.all():
            contributions[str(split.user.id)] = str(split.contribution)
        expense_data['contributions'] = contributions
    else:
        # Check if participants have changed and update contributions accordingly
        existing_contributions = expense_data.get('contributions', {})
        updated_contributions = {}
        
        # Only keep contributions for current participants
        for participant_id in participant_ids:
            if participant_id in existing_contributions:
                updated_contributions[participant_id] = existing_contributions[participant_id]
            else:
                # New participant - get their existing contribution from database or default to 0
                existing_split = expense.splits.filter(user_id=participant_id).first()
                updated_contributions[participant_id] = str(existing_split.contribution) if existing_split else '0'
        
        expense_data['contributions'] = updated_contributions
    
    context = {
        'group': group,
        'expense': expense,
        'participants': participants,
        'step': 3,
        'expense_data': expense_data,
        'is_editing': True,
    }
    return render(request, 'mainApp/group_expense_step3.html', context)

def track_expense_changes(expense, expense_data, new_splits_data, split_type, request):
    """Track detailed changes in expense and create a single consolidated history entry"""
    import json
    from decimal import Decimal
    
    changes = []
    detailed_changes = []
    
    # Track basic field changes
    if expense_data['title'] != expense.title:
        old_title = expense.title
        new_title = expense_data['title']
        changes.append(f"Title: '{old_title}' → '{new_title}'")
        detailed_changes.append({
            'type': 'title_changed',
            'old_value': old_title,
            'new_value': new_title,
            'description': f"Title changed from '{old_title}' to '{new_title}'"
        })
    
    if Decimal(expense_data['amount']) != expense.amount:
        old_amount = expense.amount
        new_amount = Decimal(expense_data['amount'])
        changes.append(f"Amount: PKR {old_amount} → PKR {new_amount}")
        detailed_changes.append({
            'type': 'amount_changed',
            'old_value': str(old_amount),
            'new_value': str(new_amount),
            'description': f"Amount changed from PKR {old_amount} to PKR {new_amount}"
        })
    
    if expense_data['description'] != expense.description:
        old_desc = expense.description or "No description"
        new_desc = expense_data['description'] or "No description"
        changes.append(f"Description updated")
        detailed_changes.append({
            'type': 'description_changed',
            'old_value': old_desc,
            'new_value': new_desc,
            'description': f"Description changed"
        })
    
    # Track category changes
    old_category = expense.category
    new_category_id = expense_data.get('category_id')
    new_category = Category.objects.get(id=new_category_id) if new_category_id else None
    
    if old_category != new_category:
        old_cat_name = old_category.name if old_category else "No category"
        new_cat_name = new_category.name if new_category else "No category"
        changes.append(f"Category: {old_cat_name} → {new_cat_name}")
        detailed_changes.append({
            'type': 'category_changed',
            'old_value': old_cat_name,
            'new_value': new_cat_name,
            'description': f"Category changed from '{old_cat_name}' to '{new_cat_name}'"
        })
    
    # Track split type changes
    if split_type != expense.split_type:
        old_split_display = dict(expense.SPLIT_CHOICES)[expense.split_type]
        new_split_display = dict(expense.SPLIT_CHOICES)[split_type]
        changes.append(f"Split type: {old_split_display} → {new_split_display}")
        detailed_changes.append({
            'type': 'split_type_changed',
            'old_value': expense.split_type,
            'new_value': split_type,
            'description': f"Split type changed from '{old_split_display}' to '{new_split_display}'"
        })
    
    # Track participant changes
    participant_ids = expense_data.get('participant_ids', [])
    old_participant_ids = set(expense.participants.values_list('id', flat=True))
    new_participant_ids = set(int(pid) for pid in participant_ids)
    
    if old_participant_ids != new_participant_ids:
        added_participants = new_participant_ids - old_participant_ids
        removed_participants = old_participant_ids - new_participant_ids
        
        participant_changes = []
        if added_participants:
            added_users = User.objects.filter(id__in=added_participants)
            added_names = [user.get_full_name() or user.username for user in added_users]
            participant_changes.append(f"Added: {', '.join(added_names)}")
        
        if removed_participants:
            removed_users = User.objects.filter(id__in=removed_participants)
            removed_names = [user.get_full_name() or user.username for user in removed_users]
            participant_changes.append(f"Removed: {', '.join(removed_names)}")
        
        changes.append(f"Participants: {'; '.join(participant_changes)}")
        detailed_changes.append({
            'type': 'participants_changed',
            'old_value': json.dumps(list(old_participant_ids)),
            'new_value': json.dumps(list(new_participant_ids)),
            'description': f"Participants changed: {'; '.join(participant_changes)}"
        })
    
    # Track individual contribution/split changes
    old_splits = {split.user.id: split for split in expense.splits.all()}
    contribution_changes = []
    split_changes = []
    
    for participant_id in participant_ids:
        participant_id_int = int(participant_id)
        participant = User.objects.get(id=participant_id_int)
        participant_name = participant.get_full_name() or participant.username
        
        # Get new values
        new_contribution = Decimal(expense_data.get('contributions', {}).get(str(participant_id), '0'))
        
        if split_type == 'equal':
            new_split_amount = Decimal(expense_data['amount']) / len(participant_ids)
        elif split_type == 'percentage':
            percentage = Decimal(new_splits_data.get(f'percentage_{participant_id}', '0'))
            new_split_amount = (Decimal(expense_data['amount']) * percentage) / 100
        else:  # amount
            new_split_amount = Decimal(new_splits_data.get(f'amount_{participant_id}', '0'))
        
        # Compare with old values if participant was in old splits
        if participant_id_int in old_splits:
            old_split = old_splits[participant_id_int]
            old_contribution = old_split.contribution
            old_split_amount = old_split.amount
            
            # Track contribution changes
            if old_contribution != new_contribution:
                contribution_changes.append(
                    f"{participant_name}: PKR {old_contribution} → PKR {new_contribution}"
                )
            
            # Track split amount changes
            if old_split_amount != new_split_amount:
                split_changes.append(
                    f"{participant_name}: PKR {old_split_amount} → PKR {new_split_amount}"
                )
        else:
            # New participant
            if new_contribution > 0:
                contribution_changes.append(f"{participant_name}: PKR 0 → PKR {new_contribution}")
            split_changes.append(f"{participant_name}: PKR 0 → PKR {new_split_amount}")
    
    # Add contribution and split changes to the overall changes
    if contribution_changes:
        changes.append(f"Contributions changed: {'; '.join(contribution_changes)}")
    
    if split_changes:
        changes.append(f"Split amounts changed: {'; '.join(split_changes)}")
    
    # Create a single consolidated history entry if there are any changes
    if changes:
        # Combine all changes into a single description
        full_description = "; ".join(changes)
        
        # Create one history entry with all changes combined
        ExpenseHistory.objects.create(
            expense=expense,
            action='expense_updated',
            performed_by=request.user,
            description=full_description
        )
    
    return changes

def send_expense_edit_notifications(expense, changes, performed_by):
    """Send detailed notifications to all expense participants about changes"""
    if not changes:
        return
    
    # Create a comprehensive change summary
    change_summary = "; ".join(changes)
    
    # Get all participants (including the editor)
    all_participants = list(expense.participants.all())
    
    # Create notifications for all participants
    try:
        for participant in all_participants:
            # Create notification title and message
            if participant == performed_by:
                title = f"You updated expense: {expense.title}"
                message = f"Changes made: {change_summary}"
            else:
                title = f"Expense updated: {expense.title}"
                message = f"{performed_by.get_full_name() or performed_by.username} made changes: {change_summary}"
            
            # Create notification
            notification = Notification.objects.create(
                user=participant,
                title=title,
                message=message,
                notification_type='expense_updated',
                group=expense.group,
                group_expense=expense
            )
            
            # Send real-time update
            send_notification_update(participant)
            
    except Exception as e:
        print(f"Error creating expense edit notifications: {e}")

@login_required
@expense_step_required([1, 2, 3])
def edit_group_expense_step4(request, group_id, expense_id):
    """Step 4: Finalize edit"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    expense = get_object_or_404(GroupExpense, id=expense_id, group=group)
    expense_data = get_expense_session_data(request)
    
    participant_ids = expense_data.get('participant_ids', [])
    participants = User.objects.filter(id__in=participant_ids)
    
    if request.method == 'POST':
        split_type = request.POST.get('split_type')
        
        # Track detailed changes before making any updates
        changes = track_expense_changes(expense, expense_data, request.POST, split_type, request)
        
        # Update basic expense details
        expense.title = expense_data['title']
        expense.amount = Decimal(expense_data['amount'])
        expense.description = expense_data['description']
        expense.split_type = split_type
        
        if expense_data.get('category_id'):
            expense.category = Category.objects.get(id=expense_data['category_id'])
        else:
            expense.category = None
        
        expense.save()
        
        # Update participants
        expense.participants.clear()
        for participant in participants:
            expense.participants.add(participant)
        
        # Delete old splits and create new ones
        expense.splits.all().delete()
        
        total_amount = Decimal(expense_data['amount'])
        contributions = {k: Decimal(v) for k, v in expense_data.get('contributions', {}).items()}
        
        if split_type == 'equal':
            split_amount = total_amount / len(participant_ids)
            for participant_id in participant_ids:
                participant = User.objects.get(id=participant_id)
                ExpenseSplit.objects.create(
                    expense=expense,
                    user=participant,
                    amount=split_amount,
                    contribution=contributions.get(str(participant_id), Decimal('0.0'))
                )
        elif split_type == 'percentage':
            for participant_id in participant_ids:
                percentage = Decimal(request.POST.get(f'percentage_{participant_id}', '0'))
                split_amount = (total_amount * percentage) / 100
                participant = User.objects.get(id=participant_id)
                ExpenseSplit.objects.create(
                    expense=expense,
                    user=participant,
                    amount=split_amount,
                    percentage=percentage,
                    contribution=contributions.get(str(participant_id), Decimal('0.0'))
                )
        elif split_type == 'amount':
            for participant_id in participant_ids:
                split_amount = Decimal(request.POST.get(f'amount_{participant_id}', '0'))
                participant = User.objects.get(id=participant_id)
                ExpenseSplit.objects.create(
                    expense=expense,
                    user=participant,
                    amount=split_amount,
                    contribution=contributions.get(str(participant_id), Decimal('0.0'))
                )
        
        # Send notifications if there were changes
        if changes:
            # Send detailed notifications to all participants (including editor)
            send_expense_edit_notifications(expense, changes, request.user)
        
        # Clear session data
        clear_expense_session(request)
        
        messages.success(request, f"Expense '{expense.title}' updated successfully!")
        return redirect('mainApp:group_detail', group_id=group.id)
    
    # GET request - pre-fill with existing split data for current participants only
    existing_splits = {}
    participant_ids = expense_data.get('participant_ids', [])
    
    for split in expense.splits.all():
        # Only include splits for participants that are still selected
        if str(split.user.id) in participant_ids:
            existing_splits[str(split.user.id)] = {
                'amount': str(split.amount),
                'percentage': str(split.percentage) if split.percentage else '0',
            }
    
    # Get expense data from session or create from existing expense
    if not expense_data:
        expense_data = {
            'title': expense.title,
            'amount': str(expense.amount),
            'description': expense.description,
            'category_id': expense.category.id if expense.category else None,
            'expense_id': expense_id,
        }
    
    context = {
        'group': group,
        'expense': expense,
        'participants': participants,  # Use session participants
        'categories': Category.objects.all(),
        'existing_splits': existing_splits,
        'split_type': expense.split_type,
        'step': 4,
        'expense_data': expense_data,  # Add expense_data
        'is_editing': True,  # Add is_editing flag
    }
    return render(request, 'mainApp/group_expense_step4.html', context)

# Settlement Views
@login_required
def settle_up_page(request, group_id, user_id=None):
    """Page for settling up debts"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    detailed_balance = group.get_detailed_balance_for_user(request.user)
    
    # Filter to only show users that the current user owes money to
    users_owed = {}
    for balance_item in detailed_balance:
        if balance_item['type'] == 'you_owe':
            users_owed[balance_item['user']] = {
                'amount': balance_item['amount'],
                'type': 'owes'
            }
    
    if user_id:
        # Settling with specific user
        to_user = get_object_or_404(User, id=user_id)
        if to_user not in users_owed:
            messages.error(request, "You don't owe money to this user.")
            return redirect('mainApp:group_detail', group_id=group.id)
        
        # Check if there's already a pending settlement to this user
        if group.has_pending_settlement_to_user(request.user, to_user):
            messages.warning(request, f"You already have a pending settlement request to {to_user.first_name} {to_user.last_name}. Please wait for their response.")
            return redirect('mainApp:group_detail', group_id=group.id)
        
        max_amount = users_owed[to_user]['amount']
        context = {
            'group': group,
            'to_user': to_user,
            'max_amount': max_amount,
            'single_user': True
        }
    else:
        # Show all users they owe money to
        if len(users_owed) == 1:
            # Only one user, redirect to single user settlement
            user_owed = list(users_owed.keys())[0]
            return redirect('mainApp:settle_up_single', group_id=group.id, user_id=user_owed.id)
        
        # Add pending settlement info to each user
        for user in users_owed:
            users_owed[user]['has_pending'] = group.has_pending_settlement_to_user(request.user, user)
        
        context = {
            'group': group,
            'users_owed': users_owed,
            'single_user': False
        }
    
    return render(request, 'mainApp/settle_up.html', context)

@login_required
def process_settlement(request, group_id, user_id):
    """Process a settlement request"""
    if request.method != 'POST':
        return redirect('mainApp:group_detail', group_id=group_id)
    
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    to_user = get_object_or_404(User, id=user_id)
    
    # Get the amount to settle
    settle_amount = Decimal(request.POST.get('amount', '0'))
    
    # Validate the amount
    detailed_balance = group.get_detailed_balance_for_user(request.user)
    users_owed = {}
    for balance_item in detailed_balance:
        if balance_item['type'] == 'you_owe':
            users_owed[balance_item['user']] = {
                'amount': balance_item['amount'],
                'type': 'owes'
            }
    
    if to_user not in users_owed:
        messages.error(request, "You don't owe money to this user.")
        return redirect('mainApp:group_detail', group_id=group.id)
    
    max_amount = users_owed[to_user]['amount']
    
    if settle_amount <= 0:
        messages.error(request, "Settlement amount must be greater than zero.")
        return redirect('mainApp:settle_up_single', group_id=group.id, user_id=user_id)
    
    if settle_amount > max_amount:
        messages.error(request, f"Settlement amount cannot exceed PKR {max_amount}.")
        return redirect('mainApp:settle_up_single', group_id=group.id, user_id=user_id)
    
    # Create settlement request
    settlement = SettlementRequest.objects.create(
        group=group,
        from_user=request.user,
        to_user=to_user,
        amount=settle_amount,
        notes=request.POST.get('notes', '')
    )
    
    # Create notifications for both users
    try:
        notifications = Notification.create_settlement_notification(settlement, 'settle_request')
        for notification in notifications:
            send_notification_update(notification.user)
    except Exception as e:
        print(f"Error creating settlement notifications: {e}")
    
    messages.success(request, f"Settlement request of PKR {settle_amount} sent to {to_user.first_name} {to_user.last_name}. Waiting for approval.")
    return redirect('mainApp:group_detail', group_id=group.id)

@login_required
def respond_to_settlement(request, group_id, settlement_id):
    """Approve or reject a settlement request"""
    if request.method != 'POST':
        return redirect('mainApp:group_detail', group_id=group_id)
    
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    settlement = get_object_or_404(SettlementRequest, id=settlement_id, to_user=request.user, status='pending')
    
    response = request.POST.get('response')
    
    if response == 'approve':
        settlement.status = 'approved'
        settlement.responded_at = timezone.now()
        settlement.save()
        
        # Find all unsettled splits between these two users in this group
        from_user = settlement.from_user
        to_user = settlement.to_user
        
        # Case 1: from_user owes to_user (to_user paid, from_user has splits)
        unsettled_splits_case1 = ExpenseSplit.objects.filter(
            expense__group=group,
            user=from_user,
            is_settled=False,
            expense__paid_by=to_user
        ).order_by('expense__created_at')
        
        # Case 2: to_user owes to from_user (from_user paid, to_user has splits)
        unsettled_splits_case2 = ExpenseSplit.objects.filter(
            expense__group=group,
            user=to_user,
            is_settled=False,
            expense__paid_by=from_user
        ).order_by('expense__created_at')
        
        remaining_amount = settlement.amount
        
        # First, settle splits where from_user owes to_user
        for split in unsettled_splits_case1:
            if remaining_amount <= 0:
                break
            
            if split.amount <= remaining_amount:
                split.is_settled = True
                split.settled_at = timezone.now()
                split.save()
                remaining_amount -= split.amount
            else:
                split.amount -= remaining_amount
                split.save()
                remaining_amount = 0
        
        # If there's still remaining amount, settle splits where to_user owes to from_user
        for split in unsettled_splits_case2:
            if remaining_amount <= 0:
                break
            
            if split.amount <= remaining_amount:
                split.is_settled = True
                split.settled_at = timezone.now()
                split.save()
                remaining_amount -= split.amount
            else:
                split.amount -= remaining_amount
                split.save()
                remaining_amount = 0
        
        messages.success(request, f"Settlement of PKR {settlement.amount} from {settlement.from_user.first_name} {settlement.from_user.last_name} has been approved and processed.")
        
        # Create notifications for both users
        try:
            notifications = Notification.create_settlement_notification(settlement, 'settle_approved')
            for notification in notifications:
                send_notification_update(notification.user)
        except Exception as e:
            print(f"Error creating settlement approval notifications: {e}")
        
    elif response == 'reject':
        settlement.status = 'rejected'
        settlement.responded_at = timezone.now()
        settlement.save()
        
        messages.info(request, f"Settlement request of PKR {settlement.amount} from {settlement.from_user.first_name} {settlement.from_user.last_name} has been rejected.")
        
        # Create notifications for both users
        try:
            notifications = Notification.create_settlement_notification(settlement, 'settle_rejected')
            for notification in notifications:
                send_notification_update(notification.user)
        except Exception as e:
            print(f"Error creating settlement rejection notifications: {e}")
    
    return redirect('mainApp:group_detail', group_id=group.id)

@login_required
def remind_payment(request, group_id):
    """Show reminder options or send reminder"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    detailed_balance = group.get_detailed_balance_for_user(request.user)
    
    # Get users that owe money to current user
    users_owed_by = []
    for balance_item in detailed_balance:
        if balance_item['type'] == 'owed_to_you':
            # Check if reminder can be sent (24-hour cooldown)
            can_remind = PaymentReminder.can_send_reminder(
                request.user, balance_item['user'], group
            )
            next_reminder_time = PaymentReminder.get_next_reminder_time(
                request.user, balance_item['user'], group
            )
            
            users_owed_by.append({
                'user': balance_item['user'],
                'amount': balance_item['amount'],
                'can_remind': can_remind,
                'next_reminder_time': next_reminder_time
            })
    
    if not users_owed_by:
        messages.info(request, "No one owes you money in this group.")
        return redirect('mainApp:group_detail', group_id=group.id)
    
    # If only one user, redirect to reminder type selection
    if len(users_owed_by) == 1:
        return redirect('mainApp:remind_payment_type', 
                       group_id=group.id, 
                       user_id=users_owed_by[0]['user'].id)
    
    context = {
        'group': group,
        'users_owed_by': users_owed_by,
    }
    return render(request, 'mainApp/remind_payment_select_user.html', context)

@login_required
def remind_payment_type(request, group_id, user_id):
    """Select reminder type (email or notification)"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    to_user = get_object_or_404(User, id=user_id, expense_groups=group)
    
    # Verify that the user owes money to current user
    detailed_balance = group.get_detailed_balance_for_user(request.user)
    user_owes_amount = None
    
    for balance_item in detailed_balance:
        if (balance_item['type'] == 'owed_to_you' and 
            balance_item['user'] == to_user):
            user_owes_amount = balance_item['amount']
            break
    
    if user_owes_amount is None:
        messages.error(request, "This user doesn't owe you money.")
        return redirect('mainApp:group_detail', group_id=group.id)
    
    # Check cooldown
    can_remind = PaymentReminder.can_send_reminder(request.user, to_user, group)
    if not can_remind:
        next_reminder_time = PaymentReminder.get_next_reminder_time(request.user, to_user, group)
        messages.warning(request, f"You can send next reminder after {next_reminder_time.strftime('%B %d, %Y at %I:%M %p')}.")
        return redirect('mainApp:group_detail', group_id=group.id)
    
    if request.method == 'POST':
        reminder_type = request.POST.get('reminder_type')
        
        if reminder_type in ['email', 'notification']:
            # Create reminder record
            reminder = PaymentReminder.objects.create(
                group=group,
                from_user=request.user,
                to_user=to_user,
                amount=user_owes_amount,
                reminder_type=reminder_type
            )
            
            # Send reminder
            if reminder_type == 'email':
                success = send_payment_reminder_email(reminder)
                if success:
                    messages.success(request, f"Payment reminder email sent to {to_user.get_full_name() or to_user.username}.")
                else:
                    messages.error(request, "Failed to send email reminder.")
            else:  # notification
                send_payment_reminder_notification(reminder)
                messages.success(request, f"Payment reminder notification sent to {to_user.get_full_name() or to_user.username}.")
            
            return redirect('mainApp:group_detail', group_id=group.id)
        else:
            messages.error(request, "Invalid reminder type selected.")
    
    context = {
        'group': group,
        'to_user': to_user,
        'amount': user_owes_amount,
    }
    return render(request, 'mainApp/remind_payment_type.html', context)

def send_payment_reminder_email(reminder):
    """Send payment reminder via email"""
    from django.core.mail import send_mail
    from django.conf import settings
    
    subject = f"Payment Reminder - {reminder.group.name}"
    
    from_user_name = reminder.from_user.get_full_name() or reminder.from_user.username
    to_user_name = reminder.to_user.get_full_name() or reminder.to_user.username
    
    message = f"""
Hello {to_user_name},

This is a gentle reminder that you owe PKR {reminder.amount} to {from_user_name} in the group "{reminder.group.name}".

Please settle this amount when convenient.

Best regards,
HisaabKaro Team
    """
    
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [reminder.to_user.email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending reminder email: {e}")
        return False

def send_payment_reminder_notification(reminder):
    """Send payment reminder via in-app notification"""
    from_user_name = reminder.from_user.get_full_name() or reminder.from_user.username
    
    # Create notification for the user who owes money
    notification = Notification.objects.create(
        user=reminder.to_user,
        notification_type='payment_reminder',
        title=f"Payment reminder from {from_user_name}",
        message=f"You owe PKR {reminder.amount} to {from_user_name} in group {reminder.group.name}. This is a gentle reminder.",
        group=reminder.group,
        extra_data={
            'amount': str(reminder.amount),
            'from_user_id': reminder.from_user.id,
            'reminder_id': reminder.id
        }
    )
    
    # Send real-time notification
    try:
        send_notification_update(reminder.to_user)
    except Exception as e:
        print(f"Error sending real-time notification: {e}")
    
    return notification

@login_required
def leave_group(request, group_id):
    """Allow a member to leave a group (with settlement validation and admin transfer)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Invalid request method'})
    
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    
    # Check if user has any pending settlements or debts
    detailed_balance = group.get_detailed_balance_for_user(request.user)
    has_pending_balance = len(detailed_balance) > 0
    
    # Check for pending settlement requests involving the user
    pending_settlements = SettlementRequest.objects.filter(
        group=group,
        status='pending'
    ).filter(
        Q(from_user=request.user) | Q(to_user=request.user)
    ).exists()
    
    if has_pending_balance:
        return JsonResponse({
            'success': False,
            'error': 'You cannot leave the group while you have pending settlements or outstanding debts. Please settle all dues first.'
        })
    
    if pending_settlements:
        return JsonResponse({
            'success': False,
            'error': 'You cannot leave the group while you have pending settlement requests. Please resolve them first.'
        })
    
    try:
        # Check if user is the group creator and there are other members
        is_admin = group.created_by == request.user
        other_members = group.members.exclude(id=request.user.id)
        
        if is_admin and other_members.exists():
            # Transfer admin role to the oldest member (by join date)
            new_admin = other_members.order_by('groupmembership__joined_at').first()
            group.created_by = new_admin
            group.save()
            
            # Create history entry for admin transfer
            GroupHistory.objects.create(
                group=group,
                action='admin_transferred',
                performed_by=request.user,
                target_user=new_admin,
                description=f"Admin role transferred from {request.user.get_full_name() or request.user.username} to {new_admin.get_full_name() or new_admin.username}"
            )
            
            # Notify new admin
            Notification.objects.create(
                user=new_admin,
                notification_type='admin_transferred',
                title=f"You are now admin of {group.name}",
                message=f"{request.user.get_full_name() or request.user.username} left the group and transferred admin role to you.",
                group=group
            )
            try:
                send_notification_update(new_admin)
            except Exception as e:
                print(f"Error sending admin transfer notification: {e}")
        
        # Remove user from group
        group.members.remove(request.user)
        
        # Create group history entry
        GroupHistory.objects.create(
            group=group,
            action='member_left',
            performed_by=request.user,
            description=f"{request.user.get_full_name() or request.user.username} left the group"
        )
        
        # Send notifications to remaining members
        remaining_members = group.members.exclude(id=request.user.id)
        for member in remaining_members:
            Notification.objects.create(
                user=member,
                notification_type='member_left',
                title=f"Member left group: {group.name}",
                message=f"{request.user.get_full_name() or request.user.username} has left the group.",
                group=group
            )
            try:
                send_notification_update(member)
            except Exception as e:
                print(f"Error sending notification to {member.username}: {e}")
        
        return JsonResponse({'success': True})
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'An error occurred: {str(e)}'})

@login_required
def delete_group(request, group_id):
    """Initiate group deletion process - requires all members' agreement"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Invalid request method'})
    
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    
    # Check if user is the group creator
    if group.created_by != request.user:
        return JsonResponse({
            'success': False,
            'error': 'Only the group creator can initiate group deletion.'
        })
    
    # Check if all members have settled up
    all_members = group.members.all()
    has_pending_balances = False
    pending_members = []
    
    for member in all_members:
        detailed_balance = group.get_detailed_balance_for_user(member)
        if len(detailed_balance) > 0:
            has_pending_balances = True
            pending_members.append(member.get_full_name() or member.username)
    
    # Check for any pending settlement requests
    pending_settlements = SettlementRequest.objects.filter(
        group=group,
        status='pending'
    ).exists()
    
    if has_pending_balances:
        return JsonResponse({
            'success': False,
            'error': f'Cannot delete group. The following members have pending settlements: {", ".join(pending_members)}. All debts must be settled before deletion.'
        })
    
    if pending_settlements:
        return JsonResponse({
            'success': False,
            'error': 'Cannot delete group. There are pending settlement requests that need to be resolved first.'
        })
    
    try:
        # Check if there's already a pending deletion request
        existing_request, created = GroupDeletionRequest.objects.get_or_create(
            group=group,
            defaults={
                'initiated_by': request.user,
                'status': 'pending'
            }
        )
        
        if not created:
            return JsonResponse({
                'success': False,
                'error': 'A group deletion request is already pending. All members must vote before a new request can be made.'
            })
        
        # Create deletion votes for all members (initiator automatically agrees)
        for member in all_members:
            GroupDeletionVote.objects.create(
                deletion_request=existing_request,
                user=member,
                vote='agree' if member == request.user else 'pending'
            )
        
        # Send notifications to all other members
        other_members = all_members.exclude(id=request.user.id)
        for member in other_members:
            Notification.objects.create(
                user=member,
                notification_type='group_deletion_request',
                title=f"Group deletion request: {group.name}",
                message=f"{request.user.get_full_name() or request.user.username} wants to delete the group '{group.name}'. Your approval is required.",
                group=group,
                extra_data={'deletion_request_id': existing_request.id}
            )
            try:
                send_notification_update(member)
            except Exception as e:
                print(f"Error sending notification to {member.username}: {e}")
        
        # Create group history entry
        GroupHistory.objects.create(
            group=group,
            action='deletion_requested',
            performed_by=request.user,
            description=f"Group deletion requested by {request.user.get_full_name() or request.user.username}"
        )
        
        return JsonResponse({
            'success': True, 
            'message': 'Group deletion request sent to all members. The group will be deleted once everyone agrees.'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'An error occurred: {str(e)}'})

@login_required
def vote_group_deletion(request, group_id):
    """Allow members to vote on group deletion"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Invalid request method'})
    
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    vote = request.POST.get('vote')  # 'agree' or 'disagree'
    
    if vote not in ['agree', 'disagree']:
        return JsonResponse({'success': False, 'error': 'Invalid vote'})
    
    try:
        # Get the pending deletion request
        deletion_request = GroupDeletionRequest.objects.get(
            group=group,
            status='pending'
        )
        
        # Update user's vote
        deletion_vote, created = GroupDeletionVote.objects.get_or_create(
            deletion_request=deletion_request,
            user=request.user,
            defaults={'vote': vote}
        )
        
        if not created:
            deletion_vote.vote = vote
            deletion_vote.save()
        
        # Check if all members have voted
        total_members = group.members.count()
        votes = GroupDeletionVote.objects.filter(deletion_request=deletion_request)
        voted_members = votes.exclude(vote='pending').count()
        agreed_members = votes.filter(vote='agree').count()
        
        if voted_members == total_members:
            # All members have voted
            if agreed_members == total_members:
                # Everyone agreed - delete the group
                deletion_request.status = 'approved'
                deletion_request.save()
                
                # Mark group as inactive
                group.is_active = False
                group.save()
                
                # Create final group history entry
                GroupHistory.objects.create(
                    group=group,
                    action='group_deleted',
                    performed_by=request.user,
                    description=f"Group deleted after unanimous agreement"
                )
                
                # Send final notifications
                for member in group.members.all():
                    Notification.objects.create(
                        user=member,
                        notification_type='group_deleted',
                        title=f"Group deleted: {group.name}",
                        message=f"The group '{group.name}' has been deleted after unanimous agreement.",
                        extra_data={'deleted_group_name': group.name}
                    )
                    try:
                        send_notification_update(member)
                    except Exception as e:
                        print(f"Error sending notification to {member.username}: {e}")
                
                return JsonResponse({
                    'success': True, 
                    'deleted': True,
                    'message': 'Group has been deleted after unanimous agreement.'
                })
            else:
                # Not everyone agreed - cancel deletion
                deletion_request.status = 'rejected'
                deletion_request.save()
                
                # Notify all members about rejection
                for member in group.members.all():
                    Notification.objects.create(
                        user=member,
                        notification_type='group_deletion_rejected',
                        title=f"Group deletion cancelled: {group.name}",
                        message=f"Group deletion was cancelled as not all members agreed.",
                        group=group
                    )
                    try:
                        send_notification_update(member)
                    except Exception as e:
                        print(f"Error sending notification to {member.username}: {e}")
                
                return JsonResponse({
                    'success': True, 
                    'deleted': False,
                    'message': 'Group deletion cancelled as not all members agreed.'
                })
        else:
            # Still waiting for more votes
            return JsonResponse({
                'success': True, 
                'deleted': False,
                'message': f'Vote recorded. Waiting for {total_members - voted_members} more member(s) to vote.'
            })
        
    except GroupDeletionRequest.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'No pending deletion request found'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'An error occurred: {str(e)}'})

@login_required
def home_chart_data(request):
    """Get chart data for home page - Group vs Personal expenses"""
    # Support both GET and POST requests
    if request.method == 'GET':
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
    else:
        import json
        data = json.loads(request.body)
        period_type = data.get('period_type')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        # Parse dates for POST requests
        if period_type == 'day':
            target_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            start_date = end_date = target_date
        elif period_type == 'month':
            target_date = datetime.strptime(start_date, '%Y-%m').date().replace(day=1)
            start_date = target_date
            # Get last day of month
            if target_date.month == 12:
                end_date = target_date.replace(year=target_date.year + 1, month=1, day=1) - timedelta(days=1)
            else:
                end_date = target_date.replace(month=target_date.month + 1, day=1) - timedelta(days=1)
    
    # Parse dates for GET requests
    if isinstance(start_date, str):
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    if isinstance(end_date, str):
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    # Get personal expenses
    personal_total = PersonalExpense.objects.filter(
        user=request.user,
        date__gte=start_date,
        date__lte=end_date
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    # Get group expenses (user's share)
    user_groups = request.user.expense_groups.all()
    group_total = 0
    
    for group in user_groups:
        group_expenses = GroupExpense.objects.filter(
            group=group,
            date__gte=start_date,
            date__lte=end_date
        )
        
        for expense in group_expenses:
            user_split = expense.splits.filter(user=request.user).first()
            if user_split:
                group_total += float(user_split.amount)
    
    # Return data in format expected by Chart.js
    labels = ['Personal Expenses', 'Group Expenses']
    data = [float(personal_total), group_total]
    
    return JsonResponse({
        'labels': labels,
        'data': data
    })

@login_required
def personal_chart_data(request):
    """Get chart data for personal expenses by category"""
    # Support both GET and POST requests
    if request.method == 'GET':
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
    else:
        import json
        data = json.loads(request.body)
        period_type = data.get('period_type')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        # Parse dates for POST requests
        if period_type == 'day':
            target_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            start_date = end_date = target_date
        elif period_type == 'month':
            target_date = datetime.strptime(start_date, '%Y-%m').date().replace(day=1)
            start_date = target_date
            if target_date.month == 12:
                end_date = target_date.replace(year=target_date.year + 1, month=1, day=1) - timedelta(days=1)
            else:
                end_date = target_date.replace(month=target_date.month + 1, day=1) - timedelta(days=1)
    
    # Parse dates for GET requests
    if isinstance(start_date, str):
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    if isinstance(end_date, str):
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    # Get expenses by category
    expenses_by_category = PersonalExpense.objects.filter(
        user=request.user,
        date__gte=start_date,
        date__lte=end_date
    ).values('category__name').annotate(total=Sum('amount')).order_by('-total')
    
    labels = []
    data = []
    
    for item in expenses_by_category:
        category_name = item['category__name'] or 'Uncategorized'
        amount = float(item['total'])
        labels.append(category_name)
        data.append(amount)
    
    return JsonResponse({
        'labels': labels,
        'data': data
    })

@login_required
def groups_chart_data(request):
    """Get chart data for spending by group"""
    # Support both GET and POST requests
    if request.method == 'GET':
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
    else:
        import json
        data = json.loads(request.body)
        period_type = data.get('period_type')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        # Parse dates for POST requests
        if period_type == 'day':
            target_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            start_date = end_date = target_date
        elif period_type == 'month':
            target_date = datetime.strptime(start_date, '%Y-%m').date().replace(day=1)
            start_date = target_date
            if target_date.month == 12:
                end_date = target_date.replace(year=target_date.year + 1, month=1, day=1) - timedelta(days=1)
            else:
                end_date = target_date.replace(month=target_date.month + 1, day=1) - timedelta(days=1)
    
    # Parse dates for GET requests
    if isinstance(start_date, str):
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    if isinstance(end_date, str):
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    # Get user's groups and their spending
    user_groups = request.user.expense_groups.all()
    group_data = []
    
    for group in user_groups:
        group_expenses = GroupExpense.objects.filter(
            group=group,
            date__gte=start_date,
            date__lte=end_date
        )
        
        group_total = 0
        for expense in group_expenses:
            user_split = expense.splits.filter(user=request.user).first()
            if user_split:
                group_total += float(user_split.amount)
        
        if group_total > 0:
            group_data.append({
                'name': group.name,
                'amount': group_total
            })
    
    # Sort by amount descending
    group_data.sort(key=lambda x: x['amount'], reverse=True)
    
    labels = [item['name'] for item in group_data]
    data = [item['amount'] for item in group_data]
    
    return JsonResponse({
        'labels': labels,
        'data': data
    })

@login_required
def group_detail_chart_data(request, group_id):
    """Get chart data for specific group - user's spending by category"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    
    # Support both GET and POST requests
    if request.method == 'GET':
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
    else:
        import json
        data = json.loads(request.body)
        period_type = data.get('period_type')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        # Parse dates for POST requests
        if period_type == 'day':
            target_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            start_date = end_date = target_date
        elif period_type == 'month':
            target_date = datetime.strptime(start_date, '%Y-%m').date().replace(day=1)
            start_date = target_date
            if target_date.month == 12:
                end_date = target_date.replace(year=target_date.year + 1, month=1, day=1) - timedelta(days=1)
            else:
                end_date = target_date.replace(month=target_date.month + 1, day=1) - timedelta(days=1)
    
    # Parse dates for GET requests
    if isinstance(start_date, str):
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    if isinstance(end_date, str):
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    # Get user's spending by category in this group
    group_expenses = GroupExpense.objects.filter(
        group=group,
        date__gte=start_date,
        date__lte=end_date
    )
    
    user_spending_by_category = {}
    
    for expense in group_expenses:
        user_split = expense.splits.filter(user=request.user).first()
        if user_split:
            category_name = expense.category.name if expense.category else 'Uncategorized'
            amount = float(user_split.amount)
            
            if category_name not in user_spending_by_category:
                user_spending_by_category[category_name] = 0
            user_spending_by_category[category_name] += amount
    
    # Sort by amount
    sorted_categories = sorted(user_spending_by_category.items(), key=lambda x: x[1], reverse=True)
    
    labels = [item[0] for item in sorted_categories]
    data = [item[1] for item in sorted_categories]
    
    return JsonResponse({
        'labels': labels,
        'data': data
    })


@login_required
def get_unread_messages_count(request, group_id):
    """Get count of unread messages for a user in a group"""
    try:
        group = get_object_or_404(Group, id=group_id)
        
        # Check if user is member of group
        if not group.members.filter(id=request.user.id).exists():
            return JsonResponse({'error': 'Not a member of this group'}, status=403)
        
        # Get user's join date
        membership = GroupMembership.objects.filter(
            user=request.user, 
            group=group
        ).first()
        
        if not membership:
            # Create membership if doesn't exist
            membership = GroupMembership.objects.create(
                user=request.user,
                group=group
            )
        
        # Get messages from join date onwards that haven't been read
        unread_messages = ChatMessage.objects.filter(
            group=group,
            timestamp__gte=membership.joined_at,
            is_deleted=False
        ).exclude(
            read_by__user=request.user
        ).exclude(
            sender=request.user  # Exclude own messages
        )
        
        unread_count = unread_messages.count()
        
        return JsonResponse({
            'success': True,
            'unread_count': min(unread_count, 100),  # Cap at 100 for display
            'display_count': f"{unread_count}+" if unread_count > 100 else str(unread_count)
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def group_chat(request, group_id):
    """Separate page for group chat"""
    group = get_object_or_404(Group, id=group_id)
    
    # Check if user is member of this group
    if not group.members.filter(id=request.user.id).exists():
        messages.error(request, "You don't have access to this group.")
        return redirect('mainApp:groups')
    
    # Get or create membership record
    membership, created = GroupMembership.objects.get_or_create(
        user=request.user,
        group=group
    )
    
    # Get recent messages from join date onwards
    recent_messages = ChatMessage.objects.filter(
        group=group,
        timestamp__gte=membership.joined_at,
        is_deleted=False
    ).select_related('sender').order_by('-timestamp')[:50]
    
    context = {
        'group': group,
        'recent_messages': reversed(recent_messages),
        'membership': membership,
    }
    
    return render(request, 'mainApp/group_chat.html', context)


@login_required
def charts_page(request, chart_type, group_id=None):
    """Separate page for charts"""
    context = {
        'chart_type': chart_type,
    }
    
    if chart_type == 'home':
        context['page_title'] = 'Home Expense Charts'
        context['chart_title'] = 'Personal vs Group Expenses'
    elif chart_type == 'personal':
        context['page_title'] = 'Personal Expense Charts'
        context['chart_title'] = 'Personal Expenses by Category'
    elif chart_type == 'groups':
        context['page_title'] = 'Groups Expense Charts'
        context['chart_title'] = 'Expenses by Group'
    elif chart_type == 'group_detail' and group_id:
        group = get_object_or_404(Group, id=group_id)
        if not group.members.filter(id=request.user.id).exists():
            messages.error(request, "You don't have access to this group.")
            return redirect('mainApp:groups')
        context['group'] = group
        context['page_title'] = f'{group.name} - Charts'
        context['chart_title'] = f'Your Expenses in {group.name}'
    else:
        messages.error(request, "Invalid chart type.")
        return redirect('mainApp:home')
    
    return render(request, 'mainApp/charts_page.html', context)


@login_required
def edit_chat_message(request, group_id, message_id):
    """Edit a chat message"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)
    
    group = get_object_or_404(Group, id=group_id)
    message = get_object_or_404(ChatMessage, id=message_id, group=group)
    
    # Check if user is member and can edit
    if not group.members.filter(id=request.user.id).exists():
        return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)
    
    if not message.can_edit(request.user):
        return JsonResponse({'success': False, 'error': 'Cannot edit this message'}, status=403)
    
    new_content = request.POST.get('content', '').strip()
    if not new_content:
        return JsonResponse({'success': False, 'error': 'Message cannot be empty'}, status=400)
    
    if message.message_type != 'text':
        return JsonResponse({'success': False, 'error': 'Cannot edit image messages'}, status=400)
    
    message.content = new_content
    message.edited_at = timezone.now()
    message.save()
    
    return JsonResponse({
        'success': True,
        'message': {
            'id': message.id,
            'content': message.content,
            'edited_at': message.edited_at.isoformat() if message.edited_at else None
        }
    })


@login_required
def delete_chat_message(request, group_id, message_id):
    """Delete a chat message"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)
    
    group = get_object_or_404(Group, id=group_id)
    message = get_object_or_404(ChatMessage, id=message_id, group=group)
    
    # Check if user is member and can delete
    if not group.members.filter(id=request.user.id).exists():
        return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)
    
    if not message.can_delete(request.user):
        return JsonResponse({'success': False, 'error': 'Cannot delete this message'}, status=403)
    
    message.soft_delete()
    
    return JsonResponse({'success': True, 'message_id': message.id})


@login_required
def send_image_message(request, group_id):
    """Send an image message"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)
    
    group = get_object_or_404(Group, id=group_id)
    
    # Check if user is member
    if not group.members.filter(id=request.user.id).exists():
        return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)
    
    if 'image' not in request.FILES:
        return JsonResponse({'success': False, 'error': 'No image provided'}, status=400)
    
    image_file = request.FILES['image']
    
    # Validate image size (max 5MB)
    if image_file.size > 5 * 1024 * 1024:
        return JsonResponse({'success': False, 'error': 'Image too large (max 5MB)'}, status=400)
    
    # Validate image type
    allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
    if image_file.content_type not in allowed_types:
        return JsonResponse({'success': False, 'error': 'Invalid image type'}, status=400)
    
    # Create the message
    message = ChatMessage.objects.create(
        group=group,
        sender=request.user,
        message_type='image',
        image=image_file
    )
    
    return JsonResponse({
        'success': True,
        'message': {
            'id': message.id,
            'sender_name': message.get_sender_name(),
            'message_type': message.message_type,
            'image_url': message.image.url if message.image else None,
            'timestamp': message.timestamp.isoformat(),
            'is_own': message.sender == request.user
        }
    })


@login_required
def download_chat_image(request, group_id, message_id):
    """Download a chat image"""
    group = get_object_or_404(Group, id=group_id)
    message = get_object_or_404(ChatMessage, id=message_id, group=group, message_type='image')
    
    # Check if user is member
    if not group.members.filter(id=request.user.id).exists():
        return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)
    
    if not message.image:
        return JsonResponse({'success': False, 'error': 'Image not found'}, status=404)
    
    from django.http import HttpResponse
    from django.utils.encoding import smart_str
    import os
    
    response = HttpResponse(message.image.read(), content_type='application/octet-stream')
    filename = os.path.basename(message.image.name)
    response['Content-Disposition'] = f'attachment; filename="{smart_str(filename)}"'
    return response


# ============== NOTIFICATION VIEWS ==============

@login_required
def notifications_page(request):
    """Display notifications page"""
    notifications = Notification.objects.filter(user=request.user)[:50]
    
    context = {
        'notifications': notifications
    }
    return render(request, 'mainApp/notifications.html', context)


@login_required
def notifications_api(request):
    """API endpoint to get user's notifications"""
    try:
        notifications = Notification.objects.filter(user=request.user)[:20]
        unread_count = Notification.objects.filter(user=request.user, is_read=False).count()
        
        notification_data = []
        for notification in notifications:
            notification_data.append({
                'id': notification.id,
                'title': notification.title,
                'message': notification.message,
                'is_read': notification.is_read,
                'time_ago': timesince(notification.created_at),
                'notification_type': notification.notification_type,
            })
        
        return JsonResponse({
            'success': True,
            'notifications': notification_data,
            'unread_count': min(unread_count, 99)
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required
def mark_notification_read(request, notification_id):
    """Mark a specific notification as read"""
    if request.method == 'POST':
        try:
            notification = get_object_or_404(Notification, id=notification_id, user=request.user)
            notification.mark_as_read()
            
            return JsonResponse({'success': True})
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'}, status=405)


@login_required
def mark_all_notifications_read(request):
    """Mark all notifications as read for the current user"""
    if request.method == 'POST':
        try:
            Notification.objects.filter(user=request.user, is_read=False).update(
                is_read=True,
                read_at=timezone.now()
            )
            
            return JsonResponse({'success': True})
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'}, status=405)


def send_notification_update(user):
    """Send notification count update via WebSocket"""
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync
    
    try:
        channel_layer = get_channel_layer()
        unread_count = Notification.objects.filter(user=user, is_read=False).count()
        
        async_to_sync(channel_layer.group_send)(
            f"user_{user.id}",
            {
                'type': 'notification_update',
                'unread_count': min(unread_count, 99)
            }
        )
    except Exception as e:
        print(f"Error sending notification update: {e}")


@login_required
def regenerate_invite_link(request, group_id):
    """Regenerate invite link for a group"""
    if request.method == 'POST':
        try:
            group = get_object_or_404(Group, id=group_id, is_active=True)
            
            # Check if user is the group admin
            if request.user != group.created_by:
                return JsonResponse({
                    'success': False, 
                    'error': 'Only group administrators can regenerate invite links.'
                }, status=403)
            
            # Generate new invite token using UUID and timestamp for uniqueness
            import uuid
            from datetime import datetime
            
            # Create a new UUID
            new_token = uuid.uuid4()
            
            # Update the group's invite token
            old_token = group.invite_token
            group.invite_token = new_token
            group.save()
            
            # Create history entry
            GroupHistory.objects.create(
                group=group,
                action='invite_link_regenerated',
                performed_by=request.user,
                description=f"Invite link was regenerated by {request.user.get_full_name() or request.user.username}"
            )
            
            # Generate the new invite link
            new_invite_link = f"{request.scheme}://{request.get_host()}/groups/join/{new_token}/"
            
            return JsonResponse({
                'success': True,
                'new_invite_link': new_invite_link,
                'message': 'Invite link has been successfully regenerated. The old link is no longer valid.'
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False, 
                'error': f'An error occurred while regenerating the invite link: {str(e)}'
            }, status=500)
    
    return JsonResponse({
        'success': False, 
        'error': 'Invalid request method. Only POST requests are allowed.'
    }, status=405)

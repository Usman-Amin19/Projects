from django.shortcuts import render, get_object_or_404, redirect
from django.db.models import Sum, Count
from django.contrib import messages
from django.http import JsonResponse
from decimal import Decimal
from datetime import datetime, date, timedelta
from .models import PersonalExpense, GroupExpense, Group, Category, ExpenseSplit, GroupHistory, UserProfile, ExpenseHistory, SettlementRequest, ChatMessage, GroupMembership, ChatMessageRead
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
from .forms import CustomUserRegistrationForm, CustomUserLoginForm, CustomPasswordResetForm, CustomSetPasswordForm

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
    """View for the user's profile page with editing capabilities"""
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'update_profile':
            # Update profile information
            first_name = request.POST.get('first_name', '').strip()
            last_name = request.POST.get('last_name', '').strip()
            email = request.POST.get('email', '').strip().lower()
            
            # Validation
            if not first_name:
                messages.error(request, "First name is required.")
                return redirect('mainApp:profile')
            
            if len(first_name) > 30:
                messages.error(request, "First name must be 30 characters or less.")
                return redirect('mainApp:profile')
                
            if len(last_name) > 30:
                messages.error(request, "Last name must be 30 characters or less.")
                return redirect('mainApp:profile')
            
            if not email:
                messages.error(request, "Email is required.")
                return redirect('mainApp:profile')
                
            # Basic email validation
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                messages.error(request, "Please enter a valid email address.")
                return redirect('mainApp:profile')
            
            # Check if email is already taken by another user
            if User.objects.filter(email=email).exclude(id=request.user.id).exists():
                messages.error(request, "This email is already registered with another account.")
                return redirect('mainApp:profile')
            
            # Update user information
            request.user.first_name = first_name
            request.user.last_name = last_name
            request.user.email = email
            request.user.username = email  # Email is username
            request.user.save()
            
            messages.success(request, "Profile updated successfully!")
            return redirect('mainApp:profile')
            
        elif action == 'change_password':
            # Change password
            current_password = request.POST.get('current_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            
            # Validation
            if not current_password:
                messages.error(request, "Current password is required.")
                return redirect('mainApp:profile')
                
            if not request.user.check_password(current_password):
                messages.error(request, "Current password is incorrect.")
                return redirect('mainApp:profile')
            
            if not new_password:
                messages.error(request, "New password is required.")
                return redirect('mainApp:profile')
                
            if len(new_password) < 8:
                messages.error(request, "New password must be at least 8 characters long.")
                return redirect('mainApp:profile')
            
            if new_password != confirm_password:
                messages.error(request, "New passwords do not match.")
                return redirect('mainApp:profile')
                
            # Additional password strength validation
            if new_password.lower() in [request.user.first_name.lower(), request.user.last_name.lower(), request.user.email.lower()]:
                messages.error(request, "Password cannot be similar to your personal information.")
                return redirect('mainApp:profile')
            
            # Update password
            request.user.set_password(new_password)
            request.user.save()
            
            # Update session to keep user logged in
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(request, request.user)
            
            messages.success(request, "Password changed successfully!")
            return redirect('mainApp:profile')
    
    # GET request
    context = {
        'user': request.user,
    }
    return render(request, 'mainApp/profile.html', context)

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
    user_groups = Group.objects.filter(members=request.user, is_active=True)
    
    group_data = []
    for group in user_groups:
        balance = group.get_balance_for_user(request.user)
        group_data.append({
            'group': group,
            'balance': balance,
            'you_owe': balance < 0,
            'you_are_owed': balance > 0,
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
    
    context = {
        'group': group,
        'expenses': expenses,
        'balance': balance,
        'detailed_balance': detailed_balance,
        'you_owe': balance < 0,
        'you_are_owed': balance > 0,
        'has_pending_settlements': has_pending_settlements,
        'pending_settlements': pending_settlements_to_approve,
        'history': history,
        'user': request.user,
    }
    return render(request, 'mainApp/group_detail.html', context)

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
            description=f"Expense '{expense.title}' (${expense.amount}) was deleted"
        )
        
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
        return redirect('mainApp:group_expense_step2', group_id=group_id)
    
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
        return redirect('mainApp:group_expense_step3', group_id=group_id)
    
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
        return redirect('mainApp:group_expense_step4', group_id=group_id)
    
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
    return render(request, 'mainApp/add_group_expense_step4.html', context)

# ============== EDIT EXPENSE STEP VIEWS ==============

@login_required
def edit_group_expense_step1(request, group_id, expense_id):
    """Step 1: Edit basic expense details"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    expense = get_object_or_404(GroupExpense, id=expense_id, group=group)
    
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
        request.session['expense_data'] = expense_data
        request.session.modified = True
        
        messages.success(request, "Basic details updated! Now review participants.")
        return redirect('mainApp:group_expense_step2', group_id=group_id, expense_id=expense_id)
    
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
        
        # Update session data
        expense_data.update({
            'participant_ids': participant_ids,
            'step_2_completed': True,
        })
        request.session['expense_data'] = expense_data
        request.session.modified = True
        
        messages.success(request, "Participants updated! Now review contributions.")
        return redirect('mainApp:group_expense_step3', group_id=group_id, expense_id=expense_id)
    
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
        return redirect('mainApp:group_expense_step4', group_id=group_id, expense_id=expense_id)
    
    # GET request - pre-fill with existing contributions
    if not expense_data.get('contributions'):
        contributions = {}
        for split in expense.splits.all():
            contributions[str(split.user.id)] = str(split.contribution)
        expense_data['contributions'] = contributions
    
    context = {
        'group': group,
        'expense': expense,
        'participants': participants,
        'step': 3,
        'expense_data': expense_data,
        'is_editing': True,
    }
    return render(request, 'mainApp/group_expense_step3.html', context)

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
        
        # Track changes for history
        changes = []
        
        # Update basic expense details
        old_title = expense.title
        old_amount = expense.amount
        old_description = expense.description
        
        if expense_data['title'] != old_title:
            changes.append(f"Title changed from '{old_title}' to '{expense_data['title']}'")
        if Decimal(expense_data['amount']) != old_amount:
            changes.append(f"Amount changed from PKR{old_amount} to PKR{expense_data['amount']}")
        if expense_data['description'] != old_description:
            changes.append(f"Description updated")
        
        # Update expense
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
        old_participants = set(expense.participants.all())
        new_participants = set(participants)
        
        if old_participants != new_participants:
            changes.append("Participants updated")
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
        
        # Create history entries
        if changes:
            ExpenseHistory.objects.create(
                expense=expense,
                action='modified',
                performed_by=request.user,
                description=f"Expense updated: {'; '.join(changes)}"
            )
            
            GroupHistory.objects.create(
                group=group,
                action='expense_modified',
                performed_by=request.user,
                description=f"Expense '{expense.title}' was modified"
            )
        
        # Clear session data
        clear_expense_session(request)
        
        messages.success(request, f"Expense '{expense.title}' updated successfully!")
        return redirect('mainApp:group_detail', group_id=group.id)
    
    # GET request - pre-fill with existing split data
    existing_splits = {}
    for split in expense.splits.all():
        existing_splits[str(split.user.id)] = {
            'amount': str(split.amount),
            'percentage': str(split.percentage) if split.percentage else '0',
        }
    
    context = {
        'group': group,
        'expense': expense,
        'participants': expense.participants.all(),
        'categories': Category.objects.all(),
        'existing_splits': existing_splits,
        'split_type': expense.split_type,
        'step': 4
    }
    return render(request, 'mainApp/group_expense_step4.html', context)

# Settlement Views
@login_required
def settle_up_page(request, group_id, user_id=None):
    """Page for settling up debts"""
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    detailed_balance = group.get_detailed_balance_for_user(request.user)
    
    # Filter to only show users that the current user owes money to
    users_owed = {user: data for user, data in detailed_balance.items() 
                  if data['type'] == 'owes'}
    
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
    users_owed = {user: data for user, data in detailed_balance.items() 
                  if data['type'] == 'owes'}
    
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
    SettlementRequest.objects.create(
        group=group,
        from_user=request.user,
        to_user=to_user,
        amount=settle_amount,
        notes=request.POST.get('notes', '')
    )
    
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
        
        # Find and settle the actual expense splits
        # Get all unsettled splits where from_user owes to_user
        unsettled_splits = ExpenseSplit.objects.filter(
            expense__group=group,
            user=settlement.from_user,
            is_settled=False,
            expense__paid_by=settlement.to_user
        ).order_by('expense__created_at')
        
        remaining_amount = settlement.amount
        
        for split in unsettled_splits:
            if remaining_amount <= 0:
                break
            
            if split.amount <= remaining_amount:
                # Settle this split completely
                split.is_settled = True
                split.settled_at = timezone.now()
                split.save()
                remaining_amount -= split.amount
            else:
                # Partially settle this split
                split.amount -= remaining_amount
                split.save()
                remaining_amount = 0
        
        messages.success(request, f"Settlement of PKR {settlement.amount} from {settlement.from_user.first_name} {settlement.from_user.last_name} has been approved and processed.")
        
    elif response == 'reject':
        settlement.status = 'rejected'
        settlement.responded_at = timezone.now()
        settlement.save()
        
        messages.info(request, f"Settlement request of PKR {settlement.amount} from {settlement.from_user.first_name} {settlement.from_user.last_name} has been rejected.")
    
    return redirect('mainApp:group_detail', group_id=group.id)

# Chart Data Views
@login_required
def home_chart_data(request):
    """Get chart data for home page - Group vs Personal expenses"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    import json
    data = json.loads(request.body)
    period_type = data.get('period_type')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    
    # Parse dates
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
    else:  # range
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
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
    
    return JsonResponse({
        'success': True,
        'data': {
            'labels': ['Personal Expenses', 'Group Expenses'],
            'values': [float(personal_total), group_total],
            'total': float(personal_total) + group_total
        }
    })

@login_required
def personal_chart_data(request):
    """Get chart data for personal expenses by category"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    import json
    data = json.loads(request.body)
    period_type = data.get('period_type')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    
    # Parse dates (same logic as home_chart_data)
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
    else:  # range
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    # Get expenses by category
    expenses_by_category = PersonalExpense.objects.filter(
        user=request.user,
        date__gte=start_date,
        date__lte=end_date
    ).values('category__name').annotate(total=Sum('amount')).order_by('-total')
    
    labels = []
    values = []
    total = 0
    
    for item in expenses_by_category:
        category_name = item['category__name'] or 'Uncategorized'
        amount = float(item['total'])
        labels.append(category_name)
        values.append(amount)
        total += amount
    
    return JsonResponse({
        'success': True,
        'data': {
            'labels': labels,
            'values': values,
            'total': total
        }
    })

@login_required
def groups_chart_data(request):
    """Get chart data for spending by group"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    import json
    data = json.loads(request.body)
    period_type = data.get('period_type')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    
    # Parse dates (same logic as above)
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
    else:  # range
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    # Get user's groups and their spending
    user_groups = request.user.expense_groups.all()
    group_data = []
    total = 0
    
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
            total += group_total
    
    # Sort by amount descending
    group_data.sort(key=lambda x: x['amount'], reverse=True)
    
    labels = [item['name'] for item in group_data]
    values = [item['amount'] for item in group_data]
    
    return JsonResponse({
        'success': True,
        'data': {
            'labels': labels,
            'values': values,
            'total': total
        }
    })

@login_required
def group_detail_chart_data(request, group_id):
    """Get chart data for specific group - user's spending by category"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    group = get_object_or_404(Group, id=group_id, is_active=True, members=request.user)
    
    import json
    data = json.loads(request.body)
    period_type = data.get('period_type')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    
    # Parse dates (same logic as above)
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
    else:  # range
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    # Get group's total spending
    group_expenses = GroupExpense.objects.filter(
        group=group,
        date__gte=start_date,
        date__lte=end_date
    )
    
    group_total_spent = sum(float(expense.amount) for expense in group_expenses)
    
    # Get user's spending by category in this group
    user_spending_by_category = {}
    user_total_spent = 0
    
    for expense in group_expenses:
        user_split = expense.splits.filter(user=request.user).first()
        if user_split:
            category_name = expense.category.name if expense.category else 'Uncategorized'
            amount = float(user_split.amount)
            
            if category_name not in user_spending_by_category:
                user_spending_by_category[category_name] = 0
            user_spending_by_category[category_name] += amount
            user_total_spent += amount
    
    # Sort by amount
    sorted_categories = sorted(user_spending_by_category.items(), key=lambda x: x[1], reverse=True)
    
    labels = [item[0] for item in sorted_categories]
    values = [item[1] for item in sorted_categories]
    
    return JsonResponse({
        'success': True,
        'data': {
            'labels': labels,
            'values': values,
            'user_total': user_total_spent,
            'group_total': group_total_spent,
            'user_percentage': (user_total_spent / group_total_spent * 100) if group_total_spent > 0 else 0
        }
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
        
        # Get messages since user joined that haven't been read
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

from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps


def user_not_authenticated(function=None, redirect_url='/'):
    """
    Decorator for views that checks that the user is NOT logged in, redirecting
    to the homepage if necessary by default.
    """
    def decorator(view_func):
        def _wrapped_view(request, *args, **kwargs):
            if request.user.is_authenticated:
                return redirect(redirect_url)

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    if function:
        return decorator(function)

    return decorator


def expense_step_required(required_steps, session_key='expense_data'):
    """
    Decorator that ensures user has completed required steps before accessing the current step.
    Redirects to the appropriate step if requirements are not met.
    
    Args:
        required_steps: List of steps that must be completed (e.g., [1, 2] for step 3)
        session_key: Session key where expense data is stored
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            expense_data = request.session.get(session_key, {})
            
            # Check if required steps are completed
            for step in required_steps:
                step_key = f'step_{step}_completed'
                if not expense_data.get(step_key, False):
                    messages.error(request, f"Please complete step {step} first.")
                    
                    # Redirect to the first incomplete step
                    group_id = kwargs.get('group_id')
                    expense_id = kwargs.get('expense_id')
                    
                    if expense_id:  # Editing mode
                        if step == 1:
                            return redirect('mainApp:edit_group_expense_step1', group_id=group_id, expense_id=expense_id)
                        elif step == 2:
                            return redirect('mainApp:edit_group_expense_step2', group_id=group_id, expense_id=expense_id)
                        elif step == 3:
                            return redirect('mainApp:edit_group_expense_step3', group_id=group_id, expense_id=expense_id)
                    else:  # Adding mode
                        if step == 1:
                            return redirect('mainApp:add_group_expense_step1', group_id=group_id)
                        elif step == 2:
                            return redirect('mainApp:add_group_expense_step2', group_id=group_id)
                        elif step == 3:
                            return redirect('mainApp:add_group_expense_step3', group_id=group_id)
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

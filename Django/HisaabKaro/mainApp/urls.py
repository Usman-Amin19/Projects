from django.urls import path, include
from django.conf import settings
from mainApp import views

app_name = 'mainApp'

urlpatterns = [
    path('profile/', views.profile_page, name='profile'),

    # Authentication URLs
    path('login/', views.login_page, name='login'),
    path('register/', views.register_page, name='register'),
    path('logout/', views.logout_page, name='logout'),
    path('verify-email/<uidb64>/<token>/', views.verify_email, name='verify_email'),
    
    # Password Reset URLs
    path('password-reset/', views.password_reset, name='password_reset'),
    path('password-reset/done/', views.password_reset_done, name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('password-reset-complete/', views.password_reset_complete, name='password_reset_complete'),
    
    # Terms and Privacy URLs
    path('terms-agreement/', views.terms_agreement, name='terms_agreement'),
    path('terms-of-use/', views.terms_of_use, name='terms_of_use'),
    path('privacy-policy/', views.privacy_policy, name='privacy_policy'),
    
    # Theme and Settings
    path('toggle-theme/', views.toggle_theme, name='toggle_theme'),
    
    # Main app URLs
    path('', views.home, name='home'),
    path('groups/', views.groups, name='groups'),
    path('groups/<int:group_id>/', views.group_detail, name='group_detail'),
    path('groups/create/', views.create_group, name='create_group'),
    path('groups/join/', views.join_group_form, name='join_group_form'),
    
    # Add Group Expense - 4 Step Process
    path('groups/<int:group_id>/add-expense/step1/', views.add_group_expense_step1, name='add_group_expense_step1'),
    path('groups/<int:group_id>/add-expense/step2/', views.add_group_expense_step2, name='add_group_expense_step2'),
    path('groups/<int:group_id>/add-expense/step3/', views.add_group_expense_step3, name='add_group_expense_step3'),
    path('groups/<int:group_id>/add-expense/step4/', views.add_group_expense_step4, name='add_group_expense_step4'),
    
    # Edit Group Expense - 4 Step Process
    path('groups/<int:group_id>/expenses/<int:expense_id>/edit/step1/', views.edit_group_expense_step1, name='edit_group_expense_step1'),
    path('groups/<int:group_id>/expenses/<int:expense_id>/edit/step2/', views.edit_group_expense_step2, name='edit_group_expense_step2'),
    path('groups/<int:group_id>/expenses/<int:expense_id>/edit/step3/', views.edit_group_expense_step3, name='edit_group_expense_step3'),
    path('groups/<int:group_id>/expenses/<int:expense_id>/edit/step4/', views.edit_group_expense_step4, name='edit_group_expense_step4'),
    
    # Legacy URLs (redirect to step 1)
    path('groups/<int:group_id>/add-expense/', views.add_group_expense_redirect, name='add_group_expense'),
    path('groups/<int:group_id>/expenses/<int:expense_id>/edit/', views.edit_group_expense_redirect, name='edit_group_expense'),
    
    # Settlement URLs
    path('groups/<int:group_id>/settle-up/', views.settle_up_page, name='settle_up'),
    path('groups/<int:group_id>/settle-up/<int:user_id>/', views.settle_up_page, name='settle_up_single'),
    path('groups/<int:group_id>/process-settlement/<int:user_id>/', views.process_settlement, name='process_settlement'),
    path('groups/<int:group_id>/settlements/<int:settlement_id>/respond/', views.respond_to_settlement, name='respond_to_settlement'),
    
    # Chart Data URLs
    path('charts/home-data/', views.home_chart_data, name='home_chart_data'),
    path('charts/personal-data/', views.personal_chart_data, name='personal_chart_data'),
    path('charts/groups-data/', views.groups_chart_data, name='groups_chart_data'),
    path('charts/group/<int:group_id>/data/', views.group_detail_chart_data, name='group_detail_chart_data'),
    
    # Chat URLs
    path('groups/<int:group_id>/unread-messages/', views.get_unread_messages_count, name='get_unread_messages_count'),
    
    path('groups/<int:group_id>/expenses/<int:expense_id>/delete/', views.delete_group_expense, name='delete_group_expense'),
    path('groups/<int:group_id>/expenses/<int:expense_id>/history/', views.expense_history, name='expense_history'),
    path('groups/join/<uuid:invite_token>/', views.join_group, name='join_group'),
    path('personal-expenses/', views.personal_expenses, name='personal_expenses'),
    path('personal-expenses/add/', views.add_personal_expense, name='add_personal_expense'),
]

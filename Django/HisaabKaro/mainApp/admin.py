from django.contrib import admin
from .models import Category, Group, PersonalExpense, GroupExpense, ExpenseSplit

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'description', 'created_at']
    search_fields = ['name']

@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_by', 'created_at', 'is_active']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'description']
    filter_horizontal = ['members']

@admin.register(PersonalExpense)
class PersonalExpenseAdmin(admin.ModelAdmin):
    list_display = ['title', 'user', 'amount', 'category', 'date']
    list_filter = ['category', 'date', 'created_at']
    search_fields = ['title', 'description']
    date_hierarchy = 'date'

@admin.register(GroupExpense)
class GroupExpenseAdmin(admin.ModelAdmin):
    list_display = ['title', 'group', 'amount', 'paid_by', 'date']
    list_filter = ['group', 'category', 'date']
    search_fields = ['title', 'description']
    date_hierarchy = 'date'

@admin.register(ExpenseSplit)
class ExpenseSplitAdmin(admin.ModelAdmin):
    list_display = ['expense', 'user', 'amount', 'is_settled']
    list_filter = ['is_settled', 'settled_at']
    search_fields = ['expense__title', 'user__username']

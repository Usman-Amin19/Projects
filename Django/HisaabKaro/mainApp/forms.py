import re
import re
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.core.exceptions import ObjectDoesNotExist


class CustomUserRegistrationForm(forms.ModelForm):
    first_name = forms.CharField(widget=forms.TextInput(attrs={
        'placeholder': 'First Name',
        'class': 'form-control'
    }))
    last_name = forms.CharField(required=False, widget=forms.TextInput(attrs={
        'placeholder': 'Last Name',
        'class': 'form-control'
    }))
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        'placeholder': 'Email',
        'class': 'form-control'
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'placeholder': 'Password',
        'class': 'form-control'
    }))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={
        'placeholder': 'Confirm Password',
        'class': 'form-control'
    }))

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this \
                email already exists.")
        return email

    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name')
        if not first_name:
            raise forms.ValidationError("First name is required.")
        
        # Check for emojis using Unicode ranges
        emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"  # emoticons
            "\U0001F300-\U0001F5FF"  # symbols & pictographs
            "\U0001F680-\U0001F6FF"  # transport & map symbols
            "\U0001F1E0-\U0001F1FF"  # flags (iOS)
            "\U00002500-\U00002BEF"  # chinese char
            "\U00002702-\U000027B0"
            "\U00002702-\U000027B0"
            "\U000024C2-\U0001F251"
            "\U0001f926-\U0001f937"
            "\U00010000-\U0010ffff"
            "\u2640-\u2642" 
            "\u2600-\u2B55"
            "\u200d"
            "\u23cf"
            "\u23e9"
            "\u231a"
            "\ufe0f"  # dingbats
            "\u3030"
            "]+", re.UNICODE)
        
        if emoji_pattern.search(first_name):
            raise forms.ValidationError("First name cannot contain emojis or special symbols.")
        
        return first_name

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if not password:
            raise forms.ValidationError("Password is required.")
        if len(password) < 8:
            raise forms.ValidationError("Password must be atleast 8 characters long.")
        elif not re.search(r'[A-Z]', password or ''):
            raise forms.ValidationError("Password must contain at \
                least one uppercase letter.")
        elif not re.search(r'[a-z]', password or ''):
            raise forms.ValidationError("Password must contain at \
                least one lowercase letter.")
        elif not re.search(r'[0-9]', password or ''):
            raise forms.ValidationError("Password must contain at \
                least one digit.")
        elif not re.search(r'[^A-Za-z0-9]', password or ''):
            raise forms.ValidationError("Password must contain at \
                least one special character.")
        return password

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', "Passwords do not match.")
        return cleaned_data


class CustomUserLoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        'placeholder': 'Email',
        'class': 'form-control'
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'placeholder': 'Password',
        'class': 'form-control'
    }))

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("email")
        password = cleaned_data.get("password")

        if email and password:
            try:
                user = User.objects.get(email__iexact=email)
                if not user.is_active:
                    raise forms.ValidationError("Account is not verified. \
                        Please check your email's Inbox, Spam and Trash folders.")
                user = authenticate(username=user.username, password=password)
                if user is None:
                    raise forms.ValidationError("Invalid password.")
                self.user = user
            except ObjectDoesNotExist:
                raise forms.ValidationError("No user found with this email.")
        return cleaned_data


class CustomPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        'placeholder': 'Email Address',
        'class': 'form-control'
    }))
    
    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            user = User.objects.get(email__iexact=email)
            if not user.is_active:
                raise forms.ValidationError("Account not verified. \
                    Please verify your account through email before resetting your\
                    password.")
        except ObjectDoesNotExist:
            raise forms.ValidationError("No user found with this email.")
        return email


class CustomSetPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(
        label="New Password",
        widget=forms.PasswordInput(attrs={
            'placeholder': 'New Password',
            'class': 'form-control'
        })
    )
    new_password2 = forms.CharField(
        label="Confirm New Password",
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Confirm New Password',
            'class': 'form-control'
        })
    )

    def clean_new_password1(self):
        password = self.cleaned_data.get('new_password1')
        if not password:
            raise forms.ValidationError("Password is required.")
        if len(password) < 8:
            raise forms.ValidationError("Password must be at \
                least 8 characters long.")
        elif not re.search(r'[A-Z]', password):
            raise forms.ValidationError("Password must contain at \
                least one uppercase letter.")
        elif not re.search(r'[a-z]', password):
            raise forms.ValidationError("Password must contain at \
                least one lowercase letter.")
        elif not re.search(r'[0-9]', password):
            raise forms.ValidationError("Password must contain at \
                least one digit.")
        elif not re.search(r'[^A-Za-z0-9]', password):
            raise forms.ValidationError("Password must contain at \
                least one special character.")
        return password
    
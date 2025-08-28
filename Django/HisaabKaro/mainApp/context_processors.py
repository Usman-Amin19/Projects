def theme_context(request):
    """Add theme information to template context"""
    dark_mode = False
    
    if request.user.is_authenticated:
        # For authenticated users, use UserProfile
        try:
            dark_mode = request.user.userprofile.dark_mode
        except:
            dark_mode = False
    else:
        # For non-authenticated users, use session
        dark_mode = request.session.get('dark_mode', False)
    
    return {
        'is_dark_mode': dark_mode
    }

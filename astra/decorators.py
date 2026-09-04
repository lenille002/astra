from functools import wraps
from django.shortcuts import redirect


def role_required(allowed_roles=None):
    """
    Décorateur pour sécuriser l'accès aux vues selon les rôles.
    
    Exemple :
        @role_required(["admin"])
        def ma_vue(request):
            ...
    """
    if allowed_roles is None:
        allowed_roles = []

    def decorator(view_func):

        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):

            # Utilisateur non connecté
            if not request.user.is_authenticated:
                return redirect("astra:login")

            # Le superutilisateur a toujours accès
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)

            # Récupération du profil utilisateur
            try:
                user_profile = request.user.profile
                user_role = user_profile.profil_type
            except AttributeError:
                return redirect("astra:login")

            # Vérification du rôle
            if user_role in allowed_roles:
                return view_func(request, *args, **kwargs)

            # Rôle non autorisé
            return redirect("astra:login")

        return _wrapped_view

    return decorator


def verifier_role(allowed_roles=None):
    """
    Alias de compatibilité pour les vues qui utilisent :
    
        @verifier_role(...)
    
    Il utilise exactement le même système que role_required.
    """
    return role_required(allowed_roles)
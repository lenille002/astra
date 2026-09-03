from django.shortcuts import redirect

def verifier_role(roles_autorises):
    def decorator(view_func):
        def _wrapped_view(request, *args, **kwargs):
            # VÉRIFIEZ BIEN CETTE PARTIE DE VOTRE CODE :
            # Si un utilisateur n'a pas le droit ou n'est pas trouvé, 
            # NE FAITES JAMAIS : return client (ou un objet de modèle)
            
            # FAITES PLUTÔT CECI :
            # if not user_has_permission:
            #     return redirect('astra:login')
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
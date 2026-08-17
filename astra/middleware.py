from django.shortcuts import redirect
from django.urls import reverse
from urllib.parse import quote

class VerrouillageGlobalMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            url_connexion = reverse('astra:login')
        except Exception:
            url_connexion = '/login/'

        chemins_publics = [
            url_connexion,
            '/',  
        ]

        path = request.path
        if (
            path.startswith('/static/') or 
            path.startswith('/media/') or 
            path.startswith('/admin/')
        ):
            return self.get_response(request)

        if not request.user.is_authenticated:
            if path not in chemins_publics:
                # CORRECTION : On redirige vers la connexion en conservant l'URL demandée dans 'next'
                url_cible = f"{url_connexion}?next={quote(request.get_full_path())}"
                return redirect(url_cible)

        response = self.get_response(request)
        return response
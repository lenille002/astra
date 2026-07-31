from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse

class VerrouillageGlobalMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # Liste des chemins ou motifs qui restent accessibles SANS être connecté
        self.urls_libres = [
            reverse('astra:login'),       # La page racine (login par token)
            reverse('astra:connexion'),   # La page de connexion classique
            reverse('astra:register'),    # La page d'inscription
        ]

    def __call__(self, request):
        # Vérifie si l'utilisateur est authentifié (via Django ou via votre session 'connecte')
        est_authentifie = request.user.is_authenticated or request.session.get('connecte', False)
        
        # Récupère le chemin actuel
        chemin_actuel = request.path

        # Si l'utilisateur n'est PAS connecté et essaie d'accéder à une page protégée
        if not est_authentifie and not any(chemin_actuel.startswith(url) for url in self.urls_libres):
            
            # Si c'est une requête AJAX / API, on renvoie une erreur JSON 403
            if request.headers.get('x-requested-with') == 'XMLHttpRequest' or chemin_actuel.startswith('/api/'):
                return JsonResponse({'status': 'error', 'message': 'Non autorisé. Veuillez vous connecter.'}, status=403)
            
            # Sinon, redirection vers la page de login avec le paramètre ?next=
            login_url = reverse('astra:login')
            return redirect(f'{login_url}?next={chemin_actuel}')

        response = self.get_response(request)
        return response
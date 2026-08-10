from django.shortcuts import redirect
from django.http import JsonResponse
from django.urls import reverse
class VerrouillageGlobalMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.urls_libres = [
            reverse('astra:login'),       
            reverse('astra:connexion'),   
            reverse('astra:register'),    
        ]

    def __call__(self, request):
        chemin_actuel = request.path

        # CORRECTION : On laisse passer l'intégralité des routes commençant par /client/ 
        # (que ce soit pour la connexion, l'espace client ou les activités)
        if chemin_actuel.startswith('/client/'):
            return self.get_response(request)

        # Vérifie si l'utilisateur est authentifié pour le reste de l'application (Admin/Employé)
        est_authentifie = (
            request.user.is_authenticated 
            or request.session.get('connecte', False) 
        )
        
        if not est_authentifie and not any(chemin_actuel.startswith(url) for url in self.urls_libres):
            if request.headers.get('x-requested-with') == 'XMLHttpRequest' or chemin_actuel.startswith('/api/'):
                return JsonResponse({'status': 'error', 'message': 'Non autorisé. Veuillez vous connecter.'}, status=403)
            
            login_url = reverse('astra:login')
            return redirect(f'{login_url}?next={chemin_actuel}')

        response = self.get_response(request)
        return response
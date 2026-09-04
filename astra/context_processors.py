from .models import NotificationPlateforme

def notifications_processor(request):
    path = request.path.lower()
    cat = None

    # On teste les mots-clés présents dans l'URL de la page active
    if 'vente' in path:
        cat = 'ventes'
    elif 'stock' in path:
        cat = 'stocks'
    elif 'appro' in path:
        cat = 'appro'
    elif 'client' in path:
        cat = 'clients'
    elif 'fournisseur' in path:
        cat = 'fournisseurs'
    elif 'rapport' in path:
        cat = 'rapports'

    if cat:
        # Récupère uniquement les non lues qui matchent la catégorie de la page
        notifications = NotificationPlateforme.objects.filter(lu=False, categorie=cat).order_by('-id')
    else:
        notifications = NotificationPlateforme.objects.none()

    return {
        'notifications_non_lues': notifications,
        'nombre_notifications': notifications.count()
    }
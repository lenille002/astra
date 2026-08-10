from astra.models import Produit, NotificationPlateforme
from django.db.models import F, Q

def notifications_header(request):
    current_url_name = getattr(request.resolver_match, 'url_name', '') if request.resolver_match else ''
    is_stock_page = 'stock' in current_url_name

    if not is_stock_page:
        return {
            'notifications_non_lues': NotificationPlateforme.objects.none(),
            'nombre_notifications': 0,
        }

    # 1. Vérification du stock faible
    if hasattr(Produit, 'seuil_alerte'):
        stock_faible_count = Produit.objects.filter(stock__lte=F('seuil_alerte')).count()
    else:
        stock_faible_count = Produit.objects.filter(stock__lte=5).count()
    
    # S'il y a un stock faible, on s'assure qu'une notification de stock existe en base pour l'afficher dans la liste
    if stock_faible_count > 0:
        titre_stock = "Alerte Stock Faible"
        msg_stock = f"{stock_faible_count} produit(s) ont atteint le seuil d'alerte critique."
        
        # Crée la notification si elle n'existe pas déjà en non lue
        if not NotificationPlateforme.objects.filter(lu=False, titre=titre_stock).exists():
            NotificationPlateforme.objects.create(titre=titre_stock, message=msg_stock)

    # 2. Récupération des notifications non lues liées aux stocks
    notifs_non_lues = NotificationPlateforme.objects.filter(
        lu=False
    ).filter(
        Q(titre__icontains='Stock') | Q(message__icontains='Stock') | Q(titre__icontains='Produit')
    ).order_by('-date_creation')
    
    total_non_lus = notifs_non_lues.count()

    return {
        'notifications_non_lues': notifs_non_lues,
        'nombre_notifications': total_non_lus,
    }
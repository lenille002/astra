from astra.models import Produit
from django.db.models import F

def notifications_header(request):
    """
    Gère les notifications et le texte d'alerte en fonction de l'état de lecture.
    """
    # 1. Compter les produits en stock faible
    if hasattr(Produit, 'seuil_alerte'):
        stock_faible_count = Produit.objects.filter(stock__lte=F('seuil_alerte')).count()
    else:
        stock_faible_count = Produit.objects.filter(stock__lte=5).count()
    
    # 2. Récupérer l'état de lecture enregistré dans la session
    dernier_stock_lu = request.session.get('last_read_stock_count', -1)
    
    # 3. Déterminer si le stock bas est considéré comme "lu" ou "nouvelle modification"
    if stock_faible_count > 0 and stock_faible_count != dernier_stock_lu:
        stock_bas = stock_faible_count
        titre_alerte = "Alerte Stock Faible"
        message_alerte = f"{stock_faible_count} produit(s) ont atteint le seuil d'alerte critique."
        notification_lue = False
    else:
        # S'il n'y a pas de nouvelle modification depuis la lecture
        stock_bas = 0
        titre_alerte = ""
        message_alerte = ""
        notification_lue = True

    return {
        'stock_bas': stock_bas,
        'titre_alerte': titre_alerte,
        'message_alerte': message_alerte,
        'notification_lue': notification_lue,
    }
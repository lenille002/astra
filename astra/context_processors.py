from astra.models import Produit, Vente, Approvisionnement, Fournisseur, Client, NotificationPlateforme
from django.db.models import F, Q

def notifications_header(request):
    current_url_name = getattr(request.resolver_match, 'url_name', '') if request.resolver_match else ''
    path = request.path.lower()

    notifs_non_lues = NotificationPlateforme.objects.none()

    # --- 1. PAGE STOCK ---
    if 'stock' in current_url_name or 'produit' in current_url_name or 'stock' in path:
        if hasattr(Produit, 'seuil_alerte'):
            stock_faible_count = Produit.objects.filter(is_active=True, stock__lte=F('seuil_alerte')).count()
        else:
            stock_faible_count = Produit.objects.filter(is_active=True, stock__lte=5).count()
        
        if stock_faible_count > 0:
            titre_stock = "Alerte Stock Faible"
            msg_stock = f"{stock_faible_count} produit(s) ont atteint le seuil d'alerte critique."
            if not NotificationPlateforme.objects.filter(lu=False, titre=titre_stock).exists():
                NotificationPlateforme.objects.create(titre=titre_stock, message=msg_stock, lu=False)

        notifs_non_lues = NotificationPlateforme.objects.filter(
            lu=False
        ).filter(
            Q(titre__icontains='stock') | Q(message__icontains='stock') |
            Q(titre__icontains='produit') | Q(message__icontains='produit') |
            Q(titre__icontains='alerte') | Q(message__icontains='alerte')
        ).order_by('-id')

    # --- 2. PAGE VENTES ---
    elif 'vente' in current_url_name or 'vente' in path:
        total_ventes = Vente.objects.count()
        titre_vente = "Suivi des Ventes"
        msg_vente = f"{total_ventes} vente(s) enregistrée(s) au total dans le système."
        if total_ventes > 0 and not NotificationPlateforme.objects.filter(lu=False, titre=titre_vente).exists():
            NotificationPlateforme.objects.create(titre=titre_vente, message=msg_vente, lu=False)

        notifs_non_lues = NotificationPlateforme.objects.filter(
            lu=False
        ).filter(
            Q(titre__icontains='vente') | Q(message__icontains='vente') |
            Q(titre__icontains='vnt') | Q(message__icontains='vnt') |
            Q(titre__icontains='facture') | Q(message__icontains='facture')
        ).order_by('-id')

    # --- 3. PAGE APPROVISIONNEMENTS ---
    elif 'appro' in current_url_name or 'approvisionnement' in current_url_name or 'appro' in path:
        total_appros = Approvisionnement.objects.count()
        titre_appro = "Gestion des Approvisionnements"
        msg_appro = f"{total_appros} approvisionnement(s) enregistré(s)."
        if total_appros > 0 and not NotificationPlateforme.objects.filter(lu=False, titre=titre_appro).exists():
            NotificationPlateforme.objects.create(titre=titre_appro, message=msg_appro, lu=False)

        notifs_non_lues = NotificationPlateforme.objects.filter(
            lu=False
        ).filter(
            Q(titre__icontains='appro') | Q(message__icontains='appro') |
            Q(titre__icontains='commande') | Q(message__icontains='commande') |
            Q(titre__icontains='reception') | Q(message__icontains='reception')
        ).order_by('-id')

    # --- 4. PAGE CLIENTS ---
    elif 'client' in current_url_name or 'client' in path:
        total_clients = Client.objects.filter(is_active=True).count()
        titre_client = "Registre des Clients"
        msg_client = f"{total_clients} client(s) actif(s) répertorié(s)."
        if total_clients > 0 and not NotificationPlateforme.objects.filter(lu=False, titre=titre_client).exists():
            NotificationPlateforme.objects.create(titre=titre_client, message=msg_client, lu=False)

        notifs_non_lues = NotificationPlateforme.objects.filter(
            lu=False
        ).filter(
            Q(titre__icontains='client') | Q(message__icontains='client') |
            Q(titre__icontains='cahier') | Q(message__icontains='cahier') |
            Q(titre__icontains='inscription') | Q(message__icontains='inscription')
        ).order_by('-id')

    # --- 5. PAGE FOURNISSEURS ---
    elif 'fournisseur' in current_url_name or 'fournisseur' in path:
        total_fournisseurs = Fournisseur.objects.count()
        titre_fourn = "Répertoire Fournisseurs"
        msg_fourn = f"{total_fournisseurs} fournisseur(s) partenaire(s) enregistré(s)."
        if total_fournisseurs > 0 and not NotificationPlateforme.objects.filter(lu=False, titre=titre_fourn).exists():
            NotificationPlateforme.objects.create(titre=titre_fourn, message=msg_fourn, lu=False)

        notifs_non_lues = NotificationPlateforme.objects.filter(
            lu=False
        ).filter(
            Q(titre__icontains='fournisseur') | Q(message__icontains='fournisseur') |
            Q(titre__icontains='partenaire') | Q(message__icontains='partenaire')
        ).order_by('-id')

    # --- 6. PAGE RAPPORTS ---
    elif 'rapport' in current_url_name or 'rapport' in path:
        titre_rap = "Centre de Rapports"
        msg_rap = "Les données analytiques et bilans sont synchronisés en temps réel."
        if not NotificationPlateforme.objects.filter(lu=False, titre=titre_rap).exists():
            NotificationPlateforme.objects.create(titre=titre_rap, message=msg_rap, lu=False)

        notifs_non_lues = NotificationPlateforme.objects.filter(
            lu=False
        ).filter(
            Q(titre__icontains='rapport') | Q(message__icontains='rapport') |
            Q(titre__icontains='analyse') | Q(message__icontains='analyse') |
            Q(titre__icontains='statistique') | Q(message__icontains='statistique')
        ).order_by('-id')

    total_non_lus = notifs_non_lues.count()

    return {
        'notifications_non_lues': notifs_non_lues,
        'nombre_notifications': total_non_lus,
    }
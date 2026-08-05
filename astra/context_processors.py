from django.db.models import F
from astra.models import Produit, Vente, Approvisionnement, Client, Fournisseur


def notifications_globales(request):
    path = request.path.lower()

    # Débogage (à supprimer lorsque tout fonctionne)
    print(f"PATH : {path}")

    badge_count = 0
    titre_alerte = "Système"
    message_alerte = "Aucune alerte pour le moment."

    try:

        # ===========================
        # PAGE VENTE
        # ===========================
        if any(mot in path for mot in ["vente", "ventes", "facture", "sales"]):

            ventes = Vente.objects.filter(
                est_archive=False
            ).count()

            produits = Produit.objects.filter(
                is_active=True
            ).count()

            stock_critique = Produit.objects.filter(
                is_active=True,
                stock__lte=F("seuil_alerte")
            ).count()

            badge_count = ventes + stock_critique

            titre_alerte = "Ventes"

            message_alerte = (
                f"{ventes} vente(s) enregistrée(s) | "
                f"{produits} produit(s) disponible(s) | "
                f"{stock_critique} produit(s) en stock critique."
            )

        # ===========================
        # PAGE STOCK
        # ===========================
        elif any(mot in path for mot in ["stock", "stocks", "produit", "produits"]):

            badge_count = Produit.objects.filter(
                is_active=True,
                stock__lte=F("seuil_alerte")
            ).count()

            titre_alerte = "Alerte Stock"

            message_alerte = (
                f"{badge_count} produit(s) en stock critique."
                if badge_count
                else "Tous les produits sont en stock suffisant."
            )

        # ===========================
        # PAGE APPROVISIONNEMENTS
        # ===========================
        elif any(mot in path for mot in ["approvisionnement", "approvisionnements"]):

            badge_count = Approvisionnement.objects.filter(
                statut="en_attente",
                is_active=True
            ).count()

            titre_alerte = "Approvisionnements"

            message_alerte = (
                f"{badge_count} commande(s) en attente."
                if badge_count
                else "Aucun approvisionnement en attente."
            )

        # ===========================
        # PAGE CLIENTS
        # ===========================
        elif any(mot in path for mot in ["client", "clients"]):

            badge_count = Client.objects.filter(
                is_active=True
            ).count()

            titre_alerte = "Clients"

            message_alerte = (
                f"{badge_count} client(s) actif(s) enregistré(s)."
            )

        # ===========================
        # PAGE FOURNISSEURS
        # ===========================
        elif any(mot in path for mot in ["fournisseur", "fournisseurs"]):

            badge_count = Fournisseur.objects.filter(
                is_active=True
            ).count()

            titre_alerte = "Fournisseurs"

            message_alerte = (
                f"{badge_count} fournisseur(s) actif(s)."
            )

        # ===========================
        # PAGE RAPPORTS
        # ===========================
        elif any(mot in path for mot in ["rapport", "rapports"]):

            stock_critique = Produit.objects.filter(
                is_active=True,
                stock__lte=F("seuil_alerte")
            ).count()

            ventes_attente = Vente.objects.filter(
                statut="en_attente",
                est_archive=False
            ).count()

            appros_attente = Approvisionnement.objects.filter(
                statut="en_attente",
                is_active=True
            ).count()

            badge_count = (
                stock_critique
                + ventes_attente
                + appros_attente
            )

            titre_alerte = "Rapports"

            message_alerte = (
                f"{stock_critique} stock(s) critique(s), "
                f"{ventes_attente} vente(s) en attente et "
                f"{appros_attente} approvisionnement(s) en attente."
            )

        # ===========================
        # AUTRES PAGES
        # ===========================
        else:
            badge_count = 0
            titre_alerte = "Système"
            message_alerte = "Aucune alerte particulière."

    except Exception as e:
        print("Erreur notifications :", e)

        badge_count = 0
        titre_alerte = "Erreur"
        message_alerte = "Impossible de charger les notifications."

    return {
        "stock_bas": badge_count,
        "titre_alerte": titre_alerte,
        "message_alerte": message_alerte,
    }
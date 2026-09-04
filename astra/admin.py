from django.db.models import Q
from django.contrib import admin
from django.db.models import Sum
from astra.models import (
    Approvisionnement,
    Categorie,
    Client,
    Fournisseur,
    Produit,
    Token,
    TokenVerification,
    Vente,
    NotificationPlateforme,
)

admin.site.register(Categorie)
admin.site.register(Vente)
admin.site.register(Fournisseur)
admin.site.register(Approvisionnement)
admin.site.register(TokenVerification)
admin.site.register(Token)
admin.site.register(NotificationPlateforme)


@admin.register(Produit)
class ProduitAdmin(admin.ModelAdmin):
    list_display = ('reference', 'nom', 'categorie', 'prix_vente', 'stock', 'is_active')
    search_fields = ('nom', 'reference')
    list_filter = ('categorie', 'is_active')

    # Organisation du formulaire d'administration pour les ordinateurs
    fieldsets = (
        ('Informations Générales', {
            'fields': ('nom', 'categorie', 'reference', 'image', 'is_active')
        }),
        ('Prix et Stock', {
            'fields': ('prix_achat', 'prix_vente', 'stock', 'seuil_alerte')
        }),
        ('Propriétés spécifiques (Ordinateurs & Composants)', {
            'classes': ('collapse',),  # Rend la section repliable
            'fields': ('processeur', 'ram', 'stockage_disque', 'taille_ecran'),
        }),
    )


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    # On affiche 'total_calcule' au lieu de 'total_depense' qui est vide dans votre DB
    list_display = ('id', 'reference', 'nom', 'telephone', 'email', 'total_calcule', 'is_active', 'date_inscription')
    search_fields = ('nom', 'telephone', 'email', 'reference')
    list_filter = ('is_active', 'date_inscription')

    def get_queryset(self, request):
        # Cette méthode "annote" chaque client avec la somme de ses ventes
        # Cela force Django à calculer le total pour chaque client lors de la récupération de la liste
        queryset = super().get_queryset(request)
        queryset = queryset.annotate(
            total_sum=Sum('ventes__montant_total', filter=Q(ventes__est_archive=False))
        )
        return queryset

    def total_calcule(self, obj):
        # On affiche le résultat calculé par l'annotation
        return obj.total_sum or 0
    
    total_calcule.short_description = 'Total Dépense'
    total_calcule.admin_order_field = 'total_sum'
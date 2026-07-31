from django.contrib import admin
from astra.models import (
    Approvisionnement,
    Categorie,
    Client,
    Fournisseur,
    Produit,
    Token,
    TokenVerification,
    Vente,
)

admin.site.register(Categorie)
admin.site.register(Vente)
admin.site.register(Fournisseur)
admin.site.register(Approvisionnement)


@admin.register(Produit)
class ProduitAdmin(admin.ModelAdmin):
    list_display = ('reference', 'nom', 'categorie', 'prix_vente', 'stock', 'is_active')
    search_fields = ('nom', 'reference')
    list_filter = ('categorie', 'is_active')

    # C'est ici que la magie opère pour organiser le formulaire d'administration :
    fieldsets = (
        ('Informations Générales', {
            'fields': ('nom', 'categorie', 'reference', 'image', 'is_active')
        }),
        ('Prix et Stock', {
            'fields': ('prix_achat', 'prix_vente', 'stock', 'seuil_alerte')
        }),
        ('Propriétés spécifiques (Ordinateurs & Composants)', {
            'classes': ('collapse',),  # <--- Ceci rend la section repliable (cliquable)
            'fields': ('processeur', 'ram', 'stockage_disque', 'taille_ecran'),
        }),
    )


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ('id', 'nom', 'telephone', 'email', 'total_depense', 'is_active', 'date_inscription')
    search_fields = ('nom', 'telephone', 'email')
    list_filter = ('is_active', 'date_inscription')


admin.site.register(TokenVerification)
admin.site.register(Token)
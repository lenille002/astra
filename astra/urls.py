from django.urls import path
from . import views

app_name = "astra"

urlpatterns = [
    # Authentification & Pages principales
    path("", views.login_view, name="login"),
    path("connexion/", views.connexion, name="connexion"),
    path("register/", views.register, name="register"),
    path("logout/", views.deconnexion, name="logout"),
    path("accueil/", views.accueil, name="accueil"),
    path("tokens/", views.token_accueil, name="token_accueil"),

    # Fournisseurs
    path("fournisseurs/", views.fournisseurs, name="fournisseurs"),
    path("fournisseurs/supprimer/<int:pk>/", views.supprimer_fournisseur, name="supprimer_fournisseur"),
    path('fournisseurs/email/<int:fournisseur_id>/', views.envoyer_email_fournisseur, name='envoyer_email_fournisseur'),   
   
    # Ventes & Stocks
    path("vente/", views.ventes, name="ventes"),
    path("vente/details/<int:vente_id>/", views.details_vente, name="details_vente"),
    path("vente/enregistrer/", views.enregistrer_vente, name="enregistrer_vente"),
    path("vente/supprimer/<int:vente_id>/", views.supprimer_vente, name="supprimer_vente"),
    path("vente/modifier/<int:vente_id>/", views.modifier_vente, name="modifier_vente"),
    
    path("stock/", views.stock, name="stock"),
    path("stock/ajouter/", views.ajouter_produit, name="ajouter_produit"),
    path("stock/modifier/<int:product_id>/", views.modifier_produit, name="modifier_produit"),
    path("stock/supprimer/<int:product_id>/", views.supprimer_produit, name="supprimer_produit"),

    # Approvisionnements
    path("approvisionnements/", views.approvisionnements, name="approvisionnements"),
    path("approvisionnements/ajouter/", views.ajouter_approvisionnement, name="ajouter_approvisionnement"),
    path('approvisionnements/<int:pk>/details/', views.details_approvisionnement, name='detail_approvisionnement'),
    path('approvisionnements/<int:pk>/modifier/', views.modifier_approvisionnement, name='modifier_approvisionnement'),
    path('approvisionnements/<int:pk>/supprimer/', views.supprimer_approvisionnement, name='supprimer_approvisionnement'),
    
    # Rapports, Clients, Tokens & Divers
    path("rapports/", views.rapports, name="rapports"),
    path("rapports/reset-page/", views.reset_page_rapports, name="reset_page_rapports"),
    path("propos/", views.propos, name="propos"),
    
    path("clients/", views.gestion_clients, name="gestion_clients"),
    path("client/inscription/", views.client_register, name="client_register"),
    path("client/<int:client_id>/connexion/", views.client_login, name="client_login"),
    path("client/<int:client_id>/cahier/", views.detail_client_activites, name="detail_client_activites"),
    path("client/<int:client_id>/supprimer/", views.supprimer_client, name="supprimer_client"),
    path("client/<int:client_id>/modifier/", views.modifier_client, name="modifier_client"),
    path("client/<int:client_id>/espace/", views.espace_client, name="espace_client"),
    path('client/mot-de-passe-oublie/', views.mot_de_passe_oublie_client, name='mot_de_passe_oublie_client'),
    path('client/<int:client_id>/modifier-mdp/', views.modifier_mot_de_passe_client, name='modifier_mot_de_passe_client'),
    path("api/generer-tokben/", views.generer_token_api, name="generer_token_api"),
    path("login-token/", views.LoginWithTokenView.as_view(), name="login_token"),

    # Gestion des utilisateurs, permissions & paramètres
    path("utilisateurs/", views.users_page_view, name="page_utilisateurs"),
    path("api/utilisateurs/", views.api_users_list_create, name="api_users_list_create"),
    path("api/utilisateurs/<int:pk>/", views.api_user_detail_update_delete, name="api_user_detail_update_delete"),
    
    # Rôles distincts pour charger les bons fichiers HTML
    path("permissions/", views.permissions_page_view, name="permissions_page"),
    path("api/permissions/", views.api_save_permissions, name="api_save_permissions"),
    
    path("historiques/", views.historiques_page_view, name="historiques_page"),
    path("parametres/", views.parametres_page_view, name="parametres_page"),
    path("api/parametres/", views.api_save_parametres, name="api_save_parametres"),
    path('notifications/marquer-lues/', views.marquer_notifications_lues, name='marquer_lues'),
]
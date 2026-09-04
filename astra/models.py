
from datetime import timedelta
import secrets

from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.db import models
from django.db.models import Max
from django.utils import timezone


# ============================================================
# PROFIL UTILISATEUR
# ============================================================

class UserProfile(models.Model):

    PROFIL_CHOICES = [
        ("etudiant", "Étudiant"),
        ("enseignant", "Enseignant"),
        ("entreprise", "Entreprise"),
        ("admin", "Admin"),
        ("candidat", "Candidat"),
    ]

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="profile"
    )

    profil_type = models.CharField(
        max_length=20,
        choices=PROFIL_CHOICES,
        default="candidat"
    )

    def __str__(self):
        return f"{self.user.username} - {self.profil_type}"


# ============================================================
# CATEGORIES
# ============================================================

class Categorie(models.Model):

    nom = models.CharField(
        max_length=100,
        unique=True
    )

    def __str__(self):
        return self.nom


# ============================================================
# PRODUITS
# ============================================================

class Produit(models.Model):

    nom = models.CharField(
        max_length=255
    )

    categorie = models.ForeignKey(
        Categorie,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="produits"
    )

    processeur = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Ex: Intel Core i5-12400F, Apple M1"
    )

    ram = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Ex: 8Go, 16Go DDR4"
    )

    stockage_disque = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Ex: SSD 512Go NVMe"
    )

    taille_ecran = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Ex: 15.6 pouces, 13.3 pouces"
    )

    prix_achat = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0
    )

    prix_vente = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0
    )

    stock = models.PositiveIntegerField(
        default=0
    )

    seuil_alerte = models.PositiveIntegerField(
        default=5
    )

    reference = models.CharField(
        max_length=100,
        unique=True,
        blank=True,
        null=True
    )

    image = models.ImageField(
        upload_to="produits/",
        blank=True,
        null=True
    )

    is_active = models.BooleanField(
        default=True
    )

    date_creation = models.DateTimeField(
        auto_now_add=True
    )

    def save(self, *args, **kwargs):

        if not self.reference:
            dernier = Produit.objects.order_by("-id").first()

            if dernier:
                numero = dernier.id + 1
            else:
                numero = 1

            self.reference = f"PROD-{numero:04d}"

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.nom} - {self.prix_vente} FCFA"


# ============================================================
# CLIENTS
# ============================================================

class Client(models.Model):

    reference = models.CharField(
        max_length=100,
        unique=True,
        blank=True,
        null=True
    )

    nom = models.CharField(
        max_length=255
    )

    telephone = models.CharField(
        max_length=50,
        blank=True
    )

    email = models.EmailField(
        blank=True,
        null=True
    )

    date_naissance = models.DateField(
        blank=True,
        null=True
    )

    adresse = models.TextField(
        blank=True
    )

    mot_de_passe = models.CharField(
        max_length=255,
        blank=True,
        null=True
    )

    date_inscription = models.DateField(
        auto_now_add=True,
        null=True,
        blank=True
    )

    total_depense = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=0
    )

    is_active = models.BooleanField(
        default=True
    )

    def save(self, *args, **kwargs):

        # Mot de passe par défaut
        if not self.mot_de_passe:
            self.mot_de_passe = make_password("1234")

        # Génération automatique de la référence
        if not self.reference:

            max_id = Client.objects.aggregate(
                Max("id")
            )["id__max"]

            numero = (max_id or 0) + 1

            self.reference = f"CLI-{numero:04d}"

        super().save(*args, **kwargs)

    def __str__(self):

        statut = "Actif" if self.is_active else "Inactif"

        return f"{self.nom} ({self.reference}) - {statut}"


# ============================================================
# VENTES
# ============================================================

class Vente(models.Model):

    STATUT_CHOICES = [
        ("en_attente", "En attente"),
        ("confirmee", "Confirmée"),
        ("livree", "Livrée"),
    ]

    reference = models.CharField(
        max_length=100,
        unique=True
    )

    client = models.ForeignKey(
        Client,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ventes"
    )

    date_vente = models.DateTimeField(
        default=timezone.now
    )

    montant_total = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=0
    )

    mode_paiement = models.CharField(
        max_length=50,
        default="especes"
    )

    statut = models.CharField(
        max_length=50,
        choices=STATUT_CHOICES,
        default="en_attente"
    )

    est_archive = models.BooleanField(
        default=False
    )

    def __str__(self):
        return f"Vente {self.reference}"


# ============================================================
# LIGNES DE VENTE
# ============================================================

class LigneVente(models.Model):

    vente = models.ForeignKey(
        Vente,
        on_delete=models.CASCADE,
        related_name="lignes"
    )

    produit = models.ForeignKey(
        Produit,
        on_delete=models.CASCADE,
        related_name="lignes_vente"
    )

    quantite = models.PositiveIntegerField(
        default=1
    )

    prix_unitaire = models.DecimalField(
        max_digits=10,
        decimal_places=2
    )

    def total(self):
        return self.quantite * self.prix_unitaire

    def __str__(self):
        return f"{self.quantite} x {self.produit.nom}"


# Compatibilité avec l'ancien nom
DetailVente = LigneVente


# ============================================================
# FOURNISSEURS
# ============================================================

class Fournisseur(models.Model):

    nom = models.CharField(
        max_length=255
    )

    contact = models.CharField(
        max_length=255,
        blank=True
    )

    telephone = models.CharField(
        max_length=50,
        blank=True
    )

    email = models.EmailField(
        blank=True,
        null=True
    )

    mot_de_passe = models.CharField(
        max_length=255,
        default="1234"
    )

    is_active = models.BooleanField(
        default=True
    )

    def __str__(self):

        statut = "Actif" if self.is_active else "Inactif"

        return f"{self.nom} - {statut}"


# ============================================================
# APPROVISIONNEMENTS
# ============================================================

class Approvisionnement(models.Model):

    STATUT_CHOICES = [
        ("en_attente", "En attente"),
        ("confirmee", "Confirmée"),
        ("expediee", "Expédiée"),
        ("livree", "Livrée"),
        ("annulee", "Annulée"),
    ]

    reference = models.CharField(
        max_length=100,
        unique=True,
        blank=True,
        null=True
    )

    fournisseur = models.ForeignKey(
        Fournisseur,
        on_delete=models.CASCADE,
        related_name="approvisionnements"
    )

    date_creation = models.DateTimeField(
        auto_now_add=True
    )

    montant_total = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=0
    )

    statut = models.CharField(
        max_length=20,
        choices=STATUT_CHOICES,
        default="en_attente"
    )

    is_active = models.BooleanField(
        default=True
    )

    def save(self, *args, **kwargs):

        if not self.reference:

            dernier = Approvisionnement.objects.order_by("-id").first()

            if dernier:
                numero = dernier.id + 1
            else:
                numero = 1

            self.reference = f"APP-{numero:04d}"

        super().save(*args, **kwargs)

    def __str__(self):
        return self.reference or "Approvisionnement"


# ============================================================
# MOUVEMENTS DE STOCK
# ============================================================

class MouvementStock(models.Model):

    TYPE_CHOICES = [
        ("entree", "Entrée"),
        ("sortie", "Sortie"),
    ]

    produit = models.ForeignKey(
        Produit,
        on_delete=models.CASCADE,
        related_name="mouvements"
    )

    type_mouvement = models.CharField(
        max_length=20,
        choices=TYPE_CHOICES
    )

    quantite = models.PositiveIntegerField()

    date = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return f"{self.type_mouvement} - {self.produit.nom}"


# ============================================================
# TOKEN EMAIL SMTP
# ============================================================

class TokenVerification(models.Model):

    email = models.EmailField()

    token = models.CharField(
        max_length=100
    )

    role = models.CharField(
        max_length=50,
        default="caissier"
    )

    date_creation = models.DateTimeField(
        auto_now_add=True
    )

    utilise = models.BooleanField(
        default=False
    )

    def est_valide(self):

        expiration = (
            self.date_creation
            + timedelta(minutes=10)
        )

        return (
            timezone.now() < expiration
            and not self.utilise
        )

    def __str__(self):
        return f"{self.email} - {self.token}"


# ============================================================
# TOKEN DE GESTION
# ============================================================

class Token(models.Model):

    email = models.EmailField()

    valeur_token = models.CharField(
        max_length=50,
        unique=True
    )

    role = models.CharField(
        max_length=50,
        default="utilisateur"
    )

    date_creation = models.DateTimeField(
        auto_now_add=True
    )

    date_expiration = models.DateTimeField()

    def __str__(self):
        return f"{self.valeur_token} - {self.email}"


# ============================================================
# NOTIFICATIONS PLATEFORME
# ============================================================

class NotificationPlateforme(models.Model):

    CATEGORIES = (
        ("ventes", "Ventes"),
        ("stocks", "Stocks"),
        ("appro", "Approvisionnement"),
        ("clients", "Clients"),
        ("fournisseurs", "Fournisseurs"),
        ("rapports", "Rapports"),
    )

    titre = models.CharField(
        max_length=200
    )

    message = models.TextField()

    categorie = models.CharField(
        max_length=20,
        choices=CATEGORIES,
        default="clients"
    )

    lu = models.BooleanField(
        default=False
    )

    date_creation = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return f"{self.titre} - {'Lu' if self.lu else 'Non lu'}"


# ============================================================
# PARAMETRES GLOBAUX
# ============================================================

class ParametreGlobal(models.Model):

    nom_boutique = models.CharField(
        max_length=255,
        default="ASTRA TECH"
    )

    verrou_commercial = models.BooleanField(
        default=False
    )

    verrou_admin = models.BooleanField(
        default=False
    )

    seuil_stock = models.IntegerField(
        default=5
    )

    taux_tva = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=19.25
    )

    def __str__(self):
        return "Configuration Globale de la Boutique"


# ============================================================
# NOTIFICATIONS UTILISATEURS
# ============================================================

class Notification(models.Model):

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        verbose_name="Utilisateur"
    )

    titre = models.CharField(
        max_length=200,
        verbose_name="Titre"
    )

    message = models.TextField(
        verbose_name="Message"
    )

    lue = models.BooleanField(
        default=False,
        verbose_name="Lue"
    )

    date_creation = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Date de création"
    )

    url = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name="Lien associé"
    )

    class Meta:
        verbose_name = "Notification"
        verbose_name_plural = "Notifications"
        ordering = ["-date_creation"]

    def __str__(self):
        return f"{self.titre} - {self.user.username}"


# ============================================================
# UTILISATEUR ACCES
# ============================================================

class UtilisateurAcces(models.Model):

    ROLE_CHOICES = [
        ("client", "Client"),
        ("fournisseur", "Fournisseur"),
    ]

    nom = models.CharField(
        max_length=100
    )

    prenom = models.CharField(
        max_length=100
    )

    email = models.EmailField(
        unique=True
    )

    telephone = models.CharField(
        max_length=30,
        blank=True
    )

    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES
    )

    token = models.CharField(
        max_length=128,
        unique=True,
        blank=True
    )

    token_expiration = models.DateTimeField(
        null=True,
        blank=True
    )

    est_actif = models.BooleanField(
        default=True
    )

    date_inscription = models.DateTimeField(
        auto_now_add=True
    )

    def generer_token(self):

        self.token = secrets.token_urlsafe(32)

        self.token_expiration = (
            timezone.now()
            + timedelta(minutes=30)
        )

        self.save(
            update_fields=[
                "token",
                "token_expiration"
            ]
        )

        return self.token

    def token_valide(self):

        if not self.token:
            return False

        if not self.token_expiration:
            return False

        if timezone.now() >= self.token_expiration:
            return False

        if not self.est_actif:
            return False

        return True


# ============================================================
# UTILISATEUR
# ============================================================

class Utilisateur(models.Model):

    nom = models.CharField(
        max_length=150
    )

    prenom = models.CharField(
        max_length=150
    )

    email = models.EmailField(
        unique=True
    )

    telephone = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )

    role = models.CharField(
        max_length=50,
        default="client"
    )

    password = models.CharField(
        max_length=255
    )

    def __str__(self):
        return f"{self.prenom} {self.nom} - {self.role}"


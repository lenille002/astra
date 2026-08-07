from django.core.serializers.json import DjangoJSONEncoder
from datetime import timedelta
import json
import secrets
import string
import re
from functools import wraps

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.core import serializers
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.db.models import F, Q, Sum, Count
from django.db import transaction
from django.db.models import Sum, Count, Max, Q, F
from django.contrib.auth.decorators import login_required

# pyrefly: ignore [missing-import]
from rest_framework import status
# pyrefly: ignore [missing-import]
from rest_framework.response import Response
# pyrefly: ignore [missing-import]
from rest_framework.views import APIView
# pyrefly: ignore [missing-import]
from rest_framework.decorators import api_view
from django.contrib import messages

# Importation des modèles de l'application 'astra'
from astra.models import (
    Approvisionnement,
    Client,
    Fournisseur,
    MouvementStock,
    Produit,
    Vente,
    LigneVente,
    Categorie,
    Token,
)
from .serializers import EmailTokenObtainSerializer, UserSerializer

# ==========================
# DÉCORATEUR DE SÉCURITÉ
# ==========================

def verifier_acces_strict(view_func):
    """
    Vérifie si l'utilisateur est authentifié via Django OU via la session.
    Redirige vers la connexion (?next=...), ou renvoie un JSON 403 pour les API/AJAX.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        is_logged = request.user.is_authenticated or request.session.get('connecte')
        
        if not is_logged:
            is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.path.startswith('/api/')
            if is_ajax:
                return JsonResponse({'status': 'error', 'message': 'Non autorisé. Veuillez vous connecter.'}, status=403)
            
            login_url = reverse('astra:connexion')
            return redirect(f"{login_url}?next={request.path}")
            
        return view_func(request, *args, **kwargs)
    return wrapper


# ==========================
# AUTHENTIFICATION & CONNEXION
# ==========================
class LoginWithTokenView(APIView):
    def post(self, request):
        serializer = EmailTokenObtainSerializer(
            data=request.data, context={'request': request}
        )
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@ensure_csrf_cookie
def connexion(request):
    """Vue pour la connexion classique (Admin / Utilisateur avec mot de passe)"""
    next_url = request.GET.get('next') or request.POST.get('next')

    if request.method == 'POST':
        identifiant = request.POST.get('email', '').strip()
        password = request.POST.get('password')

        user = None
        if '@' in identifiant:
            user_obj = User.objects.filter(email=identifiant).first()
            if user_obj:
                user = authenticate(request, username=user_obj.username, password=password)
        else:
            user = authenticate(request, username=identifiant, password=password)

        if user is not None:
            login(request, user)
            request.session['connecte'] = True
            
            if next_url:
                return redirect(next_url)
            return redirect('astra:token_accueil')
        else:
            return render(
                request,
                'astra/connexion.html',
                {'erreur': 'Identifiant ou mot de passe incorrect.', 'next': next_url},
            )

    return render(request, 'astra/connexion.html', {'next': next_url})

@ensure_csrf_cookie
def login_view(request):
    """Vue principale (à la racine /) pour se connecter via le Token reçu par e-mail ou un code d'origine"""
    next_url = request.GET.get('next') or request.POST.get('next')
    
    if request.method == 'POST':
        token = request.POST.get('token', '').strip()
        
        codes_origine_fixes = ["ASTRA-2025-TECH", "1234"]
        
        if token in codes_origine_fixes:
            user = User.objects.filter(is_superuser=True).first()
            if not user:
                user = User.objects.first()
                
            if user:
                login(request, user)
                request.session['connecte'] = True
                
                if next_url:
                    return redirect(next_url)
                return redirect('astra:accueil')
        
        token_obj = Token.objects.filter(valeur_token=token, date_expiration__gt=timezone.now()).first()
        
        if token_obj:
            user = User.objects.filter(email=token_obj.email).first()
            if not user:
                user, _ = User.objects.get_or_create(username=token_obj.email, defaults={'email': token_obj.email})
            
            login(request, user)
            request.session['connecte'] = True
            
            if next_url:
                return redirect(next_url)
            return redirect('astra:accueil')
        else:
            return render(request, 'astra/login.html', {'error': 'Token incorrect ou expiré.', 'next': next_url})
            
    return render(request, 'astra/login.html', {'next': next_url})

def deconnexion(request):
    logout(request)
    request.session.flush()
    return redirect('astra:connexion')


def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username and password:
            User.objects.create_user(username=username, password=password)
            return redirect('astra:connexion')

    return render(request, 'astra/register.html')


# ==========================
# ACCUEIL & TABLEAU DE BORD
# ==========================
@verifier_acces_strict
def accueil(request):
    return render(request, 'astra/accueil.html')


# ==========================
# GESTION DES TOKENS & UTILISATEURS
# ==========================
@verifier_acces_strict
def token_accueil(request):
    registered_users = User.objects.all().order_by('username')
    context = {
        'registered_users': registered_users,
    }
    return render(request, 'astra/token_accueil.html', context)


@csrf_exempt
@verifier_acces_strict
def generer_token_api(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email_destinataire = data.get('email')
            role = data.get('role', 'utilisateur')
            validite_heures = int(data.get('validite', 24))

            if not email_destinataire:
                return JsonResponse({'status': 'error', 'message': "L'adresse email est requise."}, status=400)

            user_concerne = User.objects.filter(email=email_destinataire).first()
            nom_utilisateur = user_concerne.username if user_concerne else email_destinataire

            part1 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            part2 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            token_genere = f'ASTRA-{part1}-{part2}'

            Token.objects.create(
                email=email_destinataire,
                valeur_token=token_genere,
                role=role,
                date_expiration=timezone.now() + timedelta(hours=validite_heures)
            )

            lien_connexion = "http://127.0.0.1:8000"
            sujet = "Votre Token d'Accès - ASTRA TECH"
            
            message = (
                f"Bonjour,\n\n"
                f"Un nouvel accès avec le rôle [{role.upper()}] vous a été attribué sur l'application ASTRA TECH.\n\n"
                f"Voici vos informations de connexion :\n"
                f"NOM : {nom_utilisateur}\n"
                f"- MOT DE PASSE (Token) : {token_genere}\n"
                f"- lien de connexion a l'application : {lien_connexion}\n\n"
                f"Veuillez utiliser ces informations avec prudence et ne les partagez pas.\n\n"
                f"Ce token est valide pendant {validite_heures} heures.\n\n"
                f"Merci d'utiliser ASTRA TECH. Nous vous remercions pour votre confiance !\n\n"
                f"Cordialement,\n"
                f"L'équipe ASTRA TECH"
            )

            send_mail(
                subject=sujet,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email_destinataire],
                fail_silently=False,
            )

            return JsonResponse({
                'status': 'success',
                'message': f'Token envoyé avec succès à {email_destinataire}',
                'token': token_genere,
                'lien': lien_connexion,
            })

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée.'}, status=405)


@verifier_acces_strict
def users_page_view(request):
    return render(request, 'astra/page_utilisateurs.html')


@csrf_exempt
@verifier_acces_strict
def api_users_list_create(request):
    if request.method == 'GET':
        users = User.objects.all().order_by('-id')
        data = [
            {
                'id': u.id,
                'name': u.username,
                'email': u.email,
                'role': 'Super Admin' if u.is_superuser else 'Utilisateur',
                'active': u.is_active,
            }
            for u in users
        ]
        return JsonResponse(data, safe=False)

    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            name = data.get('name')
            email = data.get('email')
            role = data.get('role')

            if not name or not email:
                return JsonResponse({'status': 'error', 'message': 'Nom et email requis.'}, status=400)

            if User.objects.filter(username=name).exists():
                return JsonResponse({'status': 'error', 'message': "Ce nom d'utilisateur existe déjà."}, status=400)

            user = User.objects.create_user(username=name, email=email, password='PasswordAstra2026!')
            if role == 'Super Admin':
                user.is_superuser = True
                user.is_staff = True
                user.save()

            return JsonResponse({'status': 'success', 'message': 'Utilisateur créé avec succès.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée.'}, status=405)


@api_view(['GET', 'PATCH', 'DELETE'])
@verifier_acces_strict
def api_user_detail_update_delete(request, pk):
    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response({"error": "Utilisateur introuvable."}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = UserSerializer(user)
        return Response(serializer.data)

    elif request.method == 'PATCH':
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@verifier_acces_strict
def ventes(request):
    produits = Produit.objects.filter(stock__gt=0, is_active=True)
    ventes_list = Vente.objects.filter(est_archive=False).select_related('client').order_by('-id')
    
    total_ventes_count = ventes_list.count()
    montant_total_global = ventes_list.aggregate(total=Sum('montant_total'))['total'] or 0
    
    produits_vendus_count = 0
    try:
        for ligne in LigneVente.objects.all():
            v = getattr(ligne, 'vente', None)
            if v and not getattr(v, 'est_archive', False):
                qte = getattr(ligne, 'quantite', getattr(ligne, 'qte', getattr(ligne, 'qty', 1)))
                produits_vendus_count += int(qte or 1)
    except Exception:
        pass

    if produits_vendus_count == 0:
        try:
            mouvements = MouvementStock.objects.filter(type_mouvement="sortie")
            produits_vendus_count = sum(m.quantite for m in mouvements if m.quantite)
        except Exception:
            pass

    if produits_vendus_count == 0 and total_ventes_count > 0:
        produits_vendus_count = total_ventes_count * 1

    produits_dispo_count = Produit.objects.filter(is_active=True).count()

    context = {
        'produits': produits,
        'ventes': ventes_list,
        'total_ventes_count': total_ventes_count,
        'montant_total_global': montant_total_global,
        'produits_vendus_count': produits_vendus_count,
        'produits_dispo_count': produits_dispo_count,
    }
    return render(request, 'astra/vente.html', context)


@csrf_exempt
@verifier_acces_strict
@transaction.atomic
def enregistrer_vente(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            client_nom = data.get('client_nom', 'Client comptoir').strip()
            client_telephone = data.get('client_telephone', '').strip()
            client_email = data.get('client_email', '').strip()
            
            montant_total = float(data.get('montant_total', 0))
            montant_verse = float(data.get('montant_verse', data.get('montant_paye', 0)))
            
            mode_paiement = data.get('mode_paiement', 'especes')
            statut = data.get('statut', 'Confirmée & Payée')
            produits_panier = data.get('produits', [])

            if not produits_panier:
                return JsonResponse({'success': False, 'error': 'Le panier est vide.'}, status=400)

            if montant_verse < montant_total:
                return JsonResponse({
                    'success': False, 
                    'error': f"Montant insuffisant ! Le total est de {montant_total} FCFA, mais le montant versé est de {montant_verse} FCFA."
                }, status=400)

            nom_final = client_nom if client_nom else 'Client comptoir'

            client = None
            if client_telephone:
                client = Client.objects.filter(telephone=client_telephone).first()
            elif client_email:
                client = Client.objects.filter(email=client_email).first()
            
            if not client and nom_final != 'Client comptoir':
                client = Client.objects.filter(nom=nom_final).first()

            if client:
                updated_fields = []
                if client_telephone and client.telephone != client_telephone:
                    client.telephone = client_telephone
                    updated_fields.append('telephone')
                if client_email and client.email != client_email:
                    client.email = client_email
                    updated_fields.append('email')
                if client_nom and client.nom != client_nom:
                    client.nom = client_nom
                    updated_fields.append('nom')
                if not client.is_active:
                    client.is_active = True
                    updated_fields.append('is_active')
                    
                if updated_fields:
                    client.save(update_fields=updated_fields)
            else:
                client_defaults = {
                    'is_active': True,
                    'telephone': client_telephone,
                    'email': client_email
                }
                
                if hasattr(Client, 'reference'):
                    client_defaults['reference'] = f"CLI-{timezone.now().strftime('%Y%m%d%H%M%S%f')}"

                client = Client.objects.create(nom=nom_final, **client_defaults)

            reference = f"VNT-{timezone.now().strftime('%Y%m%d%H%M%S')}"

            produits_a_traiter = []
            for item in produits_panier:
                produit_id = item.get('id')
                qte = int(item.get('quantite', 1))

                try:
                    produit = Produit.objects.select_for_update().get(id=produit_id, is_active=True)
                except Produit.DoesNotExist:
                    raise ValueError(f"Un produit du panier (ID: {produit_id}) est introuvable.")

                if produit.stock < qte:
                    raise ValueError(f"Stock insuffisant pour '{produit.nom}'. Stock actuel : {produit.stock}, Demandé : {qte}")

                produits_a_traiter.append((produit, qte))

            vente = Vente.objects.create(
                reference=reference,
                client=client,
                montant_total=montant_total,
                mode_paiement=mode_paiement,
                statut=statut,
                date_vente=timezone.now(),
                est_archive=False
            )

            for produit, qte in produits_a_traiter:
                Produit.objects.filter(id=produit.id).update(stock=F('stock') - qte)

                MouvementStock.objects.create(
                    produit=produit,
                    type_mouvement="sortie",
                    quantite=qte
                )

                LigneVente.objects.create(
                    vente=vente,
                    produit=produit,
                    quantite=qte,
                    prix_unitaire=float(produit.prix_vente)
                )

            request.session['rapports_reset_actif'] = False

            return JsonResponse({
                'success': True, 
                'message': 'Vente enregistrée avec succès et informations du client mises à jour !', 
                'reference': reference
            })

        except ValueError as ve:
            return JsonResponse({'success': False, 'error': str(ve)}, status=400)
        except Exception as e:
            return JsonResponse({'success': False, 'error': f"Une erreur système s'est produite lors de la vente : {str(e)}"}, status=500)

    return JsonResponse({'success': False, 'error': 'Méthode non autorisée.'}, status=405)


@verifier_acces_strict
def details_vente(request, vente_id):
    vente = get_object_or_404(Vente.objects.select_related('client'), id=vente_id)
    lignes = LigneVente.objects.filter(vente=vente).select_related('produit')

    data = {
        'reference': vente.reference,
        'client': vente.client.nom if vente.client else 'Client comptoir',
        'client_telephone': vente.client.telephone if vente.client and vente.client.telephone else '',
        'client_email': vente.client.email if vente.client and vente.client.email else '',
        'date': vente.date_vente.strftime("%d/%m/%Y à %H:%M") if vente.date_vente else '',
        'montant_total': float(vente.montant_total or 0),
        'mode_paiement': getattr(vente, 'mode_paiement', 'Espèces'),
        'statut': getattr(vente, 'statut', 'Confirmée'),
        'lignes': [
            {
                'produit': l.produit.nom if l.produit else "Produit",
                'quantite': l.quantite,
                'prix_unitaire': float(l.prix_unitaire),
                'sous_total': float(l.prix_unitaire * l.quantite)
            } for l in lignes
        ]
    }
    return JsonResponse(data)


@csrf_exempt
@transaction.atomic
@verifier_acces_strict
def supprimer_vente(request, vente_id):
    if request.method in ['POST', 'DELETE']:
        try:
            vente = get_object_or_404(Vente, id=vente_id)
            vente.est_archive = True  
            vente.save()

            return JsonResponse({'success': True, 'message': 'Vente placée dans la corbeille avec succès.'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
            
    return JsonResponse({'success': False, 'error': 'Méthode non autorisée.'}, status=405)


@csrf_exempt
@transaction.atomic
@verifier_acces_strict
def modifier_vente(request, vente_id):
    vente = get_object_or_404(Vente, id=vente_id)
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            nouveau_nom = data.get('client_nom', '').strip()
            nouvel_email = data.get('client_email', '').strip()
            nouveau_telephone = data.get('client_telephone', '').strip()
            nouveau_mode = data.get('mode_paiement', 'especes')

            vente.mode_paiement = nouveau_mode
            vente.save()

            if vente.client:
                client = vente.client
                if nouveau_nom: client.nom = nouveau_nom
                if nouvel_email: client.email = nouvel_email
                if nouveau_telephone: client.telephone = nouveau_telephone
                client.save()
            elif nouveau_nom:
                client, _ = Client.objects.get_or_create(
                    nom=nouveau_nom,
                    defaults={'email': nouvel_email, 'telephone': nouveau_telephone, 'is_active': True}
                )
                vente.client = client
                vente.save()

            return JsonResponse({
                'success': True, 
                'message': 'Vente modifiée avec succès !'
            })
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)

    return JsonResponse({'success': False, 'error': 'Méthode non autorisée.'}, status=405)




# ==========================
# GESTION DES CLIENTS & CAHIER CLIENT
# ==========================
@verifier_acces_strict
def gestion_clients(request):
    filter_type = request.GET.get('filter', 'all')
    
    clients_qs = Client.objects.filter(is_active=True).annotate(
        total_depenses_calcule=Sum('ventes__montant_total', filter=Q(ventes__est_archive=False)),
        nombre_achats=Count('ventes', filter=Q(ventes__est_archive=False))
    ).order_by('-id')
    
    clients_archives = Client.objects.filter(is_active=False).order_by('-id')

    if filter_type == 'loyal':
        clients_qs = clients_qs.filter(total_depenses_calcule__gt=100000)
    elif filter_type == 'new' and hasattr(Client, 'date_inscription'):
        debut_mois = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        clients_qs = clients_qs.filter(date_inscription__gte=debut_mois)

    total_clients = Client.objects.filter(is_active=True).count()
    
    if hasattr(Client, 'date_inscription'):
        debut_mois = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        new_clients_count = Client.objects.filter(is_active=True, date_inscription__gte=debut_mois).count()
    else:
        new_clients_count = 0
    
    loyal_clients_count = Client.objects.filter(is_active=True).annotate(
        total_depenses_calcule=Sum('ventes__montant_total', filter=Q(ventes__est_archive=False))
    ).filter(total_depenses_calcule__gt=100000).count()

    context = {
        'clients': clients_qs,
        'clients_archives': clients_archives,
        'total_clients': total_clients,
        'new_clients_count': new_clients_count,
        'loyal_clients_count': loyal_clients_count,
        'current_filter': filter_type,
    }
    
    return render(request, 'astra/clients.html', context)
@login_required
def detail_client_activites(request, client_id):
    """Cahier d'activités pour un client spécifique"""
    client = get_object_or_404(Client, id=client_id)
    historique_achats = Vente.objects.filter(client=client).order_by('-date_vente')
    
    # Calcul des statistiques du client
    nombre_achats = historique_achats.count()
    total_depenses = historique_achats.aggregate(total=Sum('montant_total'))['total'] or 0

    context = {
        'client': client,
        'historique_achats': historique_achats,
        'nombre_achats': nombre_achats,
        'total_depenses': total_depenses,
    }
    return render(request, 'astra/detail_client_activites.html', context)

@login_required
def espace_client(request, client_id):
    """Affiche strictement l'espace du client correspondant à l'ID fourni dans l'URL"""
    # Récupère le client spécifique via son ID (génère une 404 s'il n'existe pas)
    client = get_object_or_404(Client, id=client_id)
    
    # Récupère uniquement les achats de ce client précis
    historique_achats = Vente.objects.filter(client=client).order_by('-date_vente')

    context = {
        'client_user': client,
        'historique_achats': historique_achats
    }
    return render(request, 'astra/espace_client.html', context)

@verifier_acces_strict
def supprimer_client(request, client_id):
    client = get_object_or_404(Client, pk=client_id)
    client.is_active = False
    client.save()
    return redirect('astra:gestion_clients')

@verifier_acces_strict
def modifier_client(request, client_id):
    client = get_object_or_404(Client, pk=client_id)
    if request.method == 'POST':
        client.nom = request.POST.get('nom', client.nom)
        client.email = request.POST.get('email', '')
        client.telephone = request.POST.get('telephone', client.telephone)
        client.adresse = request.POST.get('adresse', '')
        client.save()
    return redirect('astra:gestion_clients')

@verifier_acces_strict
def reset_page_rapports(request):
    if request.method == 'POST':
        request.session['rapports_reset_actif'] = True
        messages.success(request, "La page des rapports a été réinitialisée pour la réunion.")
    return redirect('astra:rapports')

# ==========================
# STOCKS & PRODUITS
# ==========================

def stock(request):
    produits = Produit.objects.filter(is_active=True).select_related('categorie')
    categories = Categorie.objects.all()
    
    total_produits = produits.count()
    stock_faible = produits.filter(stock__lte=F('seuil_alerte')).count() if hasattr(Produit, 'seuil_alerte') else 0
    valeur_stock = produits.aggregate(
        total=Sum(F('prix_achat') * F('stock'))
    )['total'] or 0

    context = {
        'produits': produits,
        'categories': categories,
        'total_produits': total_produits,
        'stock_faible': stock_faible,
        'valeur_stock': valeur_stock,
    }
    return render(request, 'astra/stock.html', context)


def liste_stocks(request):
    categories = Categorie.objects.prefetch_related('produit_set').all()
    produits = Produit.objects.all()
    
    context = {
        'categories': categories,
        'produits': produits,
    }
    return render(request, 'astra/liste_stocks.html', context)
 
import uuid

import uuid

@csrf_exempt
@verifier_acces_strict
def ajouter_produit(request):
    if request.method == 'POST':
        try:
            nom = request.POST.get('nom')
            categorie_id = request.POST.get('categorie_id')
            prix_achat = request.POST.get('prix_achat', 0)
            prix_vente = request.POST.get('prix_vente', 0)
            stock = request.POST.get('stock', 0)

            categorie = Categorie.objects.filter(id=categorie_id).first() if categorie_id else None

            # --- Génération automatique de la référence unique par la base / le serveur ---
            prefixe = categorie.nom[:3].upper() if categorie else "AST"
            unique_id = str(uuid.uuid4())[:4].upper()
            reference = f"{prefixe}-{unique_id}"

            Produit.objects.create(
                reference=reference,
                nom=nom,
                categorie=categorie,
                prix_achat=prix_achat,
                prix_vente=prix_vente,
                stock=stock,
                is_active=True
            )
            return JsonResponse({'status': 'success', 'message': f'Produit enregistré avec succès (Réf: {reference}) !'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée'}, status=405)
@csrf_exempt
@verifier_acces_strict
def modifier_produit(request, product_id):
    produit = get_object_or_404(Produit, id=product_id, is_active=True)
    if request.method == 'POST':
        try:
            produit.reference = request.POST.get('reference', produit.reference)
            produit.nom = request.POST.get('nom', produit.nom)
            
            categorie_id = request.POST.get('categorie_id')
            if categorie_id:
                produit.categorie = Categorie.objects.filter(id=categorie_id).first()
            else:
                produit.categorie = None
                
            produit.prix_achat = request.POST.get('prix_achat', produit.prix_achat)
            produit.prix_vente = request.POST.get('prix_vente', produit.prix_vente)
            produit.stock = request.POST.get('stock', produit.stock) # Remplacé quantite par stock
            produit.save()

            return JsonResponse({'status': 'success', 'message': 'Produit modifié avec succès !'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée'}, status=405)

@csrf_exempt
@verifier_acces_strict
def supprimer_produit(request, product_id):
    if request.method == 'POST':
        try:
            produit = get_object_or_404(Produit, id=product_id)
            produit.is_active = False
            produit.save()
            return JsonResponse({'status': 'success', 'message': 'Produit désactivé/supprimé avec succès !'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée'}, status=405)
# ==========================
# FOURNISSEURS
# ==========================
@verifier_acces_strict
def fournisseurs(request):
    if request.method == 'POST':
        supplier_id = request.POST.get('supplier_id')
        nom = request.POST.get('nom')
        contact = request.POST.get('contact')
        telephone = request.POST.get('telephone')
        email = request.POST.get('email')

        try:
            if supplier_id:  
                fournisseur = get_object_or_404(Fournisseur, id=supplier_id, is_active=True)
                fournisseur.nom = nom
                fournisseur.contact = contact
                fournisseur.telephone = telephone
                fournisseur.email = email
                fournisseur.save()
            else:  
                Fournisseur.objects.create(
                    nom=nom,
                    contact=contact,
                    telephone=telephone,
                    email=email,
                    is_active=True
                )

            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'status': 'success'})
            
            return redirect('astra:fournisseurs')

        except Exception as e:
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    liste_fournisseurs = Fournisseur.objects.filter(is_active=True)
    context = {
        'fournisseurs': liste_fournisseurs,
    }
    return render(request, 'astra/fournisseurs.html', context)


@verifier_acces_strict
def supprimer_fournisseur(request, pk):
    fournisseur = get_object_or_404(Fournisseur, pk=pk)
    fournisseur.is_active = False
    fournisseur.save()
    return redirect('astra:fournisseurs')

def envoyer_mail_fournisseur(request, pk):
    approvisionnement = get_object_or_404(Approvisionnement, pk=pk)
    
    sujet = f"Commande / Approvisionnement n° {approvisionnement.id}"
    message = "Bonjour, voici les détails de notre commande..."
    expediteur = "votre_email@gmail.com"
    destinataire = [approvisionnement.fournisseur.email]
    
    try:
        send_mail(sujet, message, expediteur, destinataire, fail_silently=False)
        approvisionnement.statut = 'Livrée'
        approvisionnement.save()
    except Exception:
        pass
# ==========================
# GESTION DES APPROVISIONNEMENTS
# ==========================
@verifier_acces_strict
def approvisionnements(request):
    if request.method == 'POST':
        fournisseur_id = request.POST.get('fournisseur')
        montant_total = request.POST.get('montant_total', 0)
        statut = request.POST.get('statut', 'en_attente')
        
        if fournisseur_id:
            Approvisionnement.objects.create(
                fournisseur_id=fournisseur_id,
                montant_total=montant_total,
                statut=statut,
                is_active=True
            )
        return redirect('astra:approvisionnements')

    liste_appros = Approvisionnement.objects.filter(is_active=True).select_related('fournisseur').all()
    fournisseurs_list = Fournisseur.objects.filter(is_active=True)
    
    context = {
        'approvisionnements': liste_appros,
        'fournisseurs': fournisseurs_list,
    }
    return render(request, 'astra/approvisionnements.html', context)


@csrf_exempt
@verifier_acces_strict
def ajouter_approvisionnement(request):
    if request.method == 'POST':
        fournisseur_id = request.POST.get('fournisseur')
        if not fournisseur_id:
            return JsonResponse({'status': 'error', 'message': 'Veuillez choisir un fournisseur.'}, status=400)
        
        try:
            fournisseur = Fournisseur.objects.get(id=fournisseur_id, is_active=True)
            Approvisionnement.objects.create(
                fournisseur=fournisseur,
                statut='en_attente',
                montant_total=0.00,
                is_active=True
            )
            
            # DÈS QU'UN NOUVEL APPROVISIONNEMENT EST FAIT, ON RÉACTIVE L'AFFICHAGE DANS LES RAPPORTS
            request.session['rapports_reset_actif'] = False

            return JsonResponse({'status': 'success', 'message': 'Approvisionnement enregistré avec succès.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
            
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée.'}, status=405)

@csrf_exempt
@verifier_acces_strict
def details_approvisionnement(request, pk):
    appro = get_object_or_404(Approvisionnement, pk=pk)
    
    montant_str = str(appro.montant_total).replace(',', '.') if appro.montant_total is not None else '0.00'

    date_str = ''
    if hasattr(appro, 'date_vente') and appro.date_vente:
        date_str = appro.date_vente.strftime('%Y-%m-%d %H:%M')
    elif hasattr(appro, 'date_creation') and appro.date_creation:
        date_str = appro.date_creation.strftime('%Y-%m-%d %H:%M')

    data = {
        'success': True,
        'id': appro.id,
        'reference': appro.reference,
        'fournisseur_id': appro.fournisseur.id if appro.fournisseur else '',
        'fournisseur': appro.fournisseur.nom if appro.fournisseur else 'N/A',
        'date': date_str,
        'montant_total': montant_str,
        'statut': appro.statut,
    }
    return JsonResponse(data)
@csrf_exempt
@verifier_acces_strict
def modifier_approvisionnement(request, pk):
    appro = get_object_or_404(Approvisionnement, pk=pk)
    if request.method == 'POST':
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
            else:
                data = request.POST

            # Ligne de débogage : imprime dans votre terminal ce que Django reçoit
            print("DONNÉES REÇUES POUR MODIFICATION :", data)

            fournisseur_id = data.get('fournisseur')
            montant_total = data.get('montant_total')
            statut = data.get('statut')

            if fournisseur_id:
                fournisseur = get_object_or_404(Fournisseur, id=fournisseur_id)
                appro.fournisseur = fournisseur
            
            if montant_total is not None and montant_total != '':
                appro.montant_total = montant_total
                
            if statut:
                appro.statut = statut

            appro.save()
            return JsonResponse({'success': True, 'message': 'Approvisionnement modifié avec succès.'})
        except Exception as e:
            print("ERREUR LORS DE LA MODIFICATION :", str(e))
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
            
    return JsonResponse({'success': False, 'error': 'Méthode non autorisée'}, status=405)

def supprimer_approvisionnement(request, pk):
    appro = get_object_or_404(Approvisionnement, pk=pk)
    if request.method == 'POST':
        try:
            appro.delete()
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Méthode non autorisée'})

@verifier_acces_strict
def rapports(request):
    reset_actif = request.session.get('rapports_reset_actif', False)
    
    total_stock_qty = Produit.objects.aggregate(total=Sum('stock'))['total'] or 0
    produits_data = list(Produit.objects.filter(is_active=True).values('nom', 'stock'))
    produits_json = json.dumps(produits_data, cls=DjangoJSONEncoder)

    if reset_actif:
        total_sales = 0
        total_appros = 0
        total_clients = 0
        total_suppliers = 0
        clients_resume = []
        dernieres_ventes = []
        derniers_appros = []
        appros_json = json.dumps([], cls=DjangoJSONEncoder)
        ventes_json = json.dumps([], cls=DjangoJSONEncoder)
    else:
        ventes_qs = Vente.objects.filter(est_archive=False).order_by('-date_vente', '-id')
        appros_qs = Approvisionnement.objects.filter(is_active=True).order_by('-id')

        total_sales = ventes_qs.aggregate(total=Sum('montant_total'))['total'] or 0
        total_appros = appros_qs.aggregate(total=Sum('montant_total'))['total'] or 0
        total_clients = Client.objects.filter(is_active=True).count()
        total_suppliers = Fournisseur.objects.filter(is_active=True).count()

        clients_resume = Client.objects.filter(is_active=True).annotate(
            nombre_achats=Count('ventes', filter=Q(ventes__est_archive=False)),                                 
            montant_total_achats=Sum('ventes__montant_total', filter=Q(ventes__est_archive=False)) 
        ).filter(montant_total_achats__gt=0).order_by('-nombre_achats', '-montant_total_achats')

        dernieres_ventes = ventes_qs[:5]

        # Regroupement par fournisseur unique pour éviter les doublons
        appros_par_fournisseur = appros_qs.values('fournisseur').annotate(
            total_montant=Sum('montant_total'),
            dernier_id=Max('id'),
            nombre_appros=Count('id')
        ).order_by('-dernier_id')

        derniers_appros = []
        appros_list = []

        for group in appros_par_fournisseur:
            f_id = group.get('fournisseur')
            if f_id:
                fournisseur_obj = Fournisseur.objects.filter(id=f_id).first()
                f_nom = fournisseur_obj.nom if fournisseur_obj else 'Fournisseur externe'
            else:
                f_nom = 'Fournisseur externe'

            subs = appros_qs.filter(fournisseur_id=f_id) if f_id else appros_qs.filter(fournisseur__isnull=True)
            sub_data = list(subs.values('id', 'reference', 'montant_total', 'statut'))
            
            dernier_app = subs.first()
            app_id = group.get('dernier_id') or 1
            ref_affichage = dernier_app.reference if (dernier_app and dernier_app.reference) else f"APP-{app_id}"

            derniers_appros.append({
                'id': app_id,
                'reference': ref_affichage,
                'fournisseur_nom': f_nom,
                'montant_total': float(group.get('total_montant') or 0),
                'nombre_appros': group.get('nombre_appros') or 1
            })

            appros_list.append({
                'fournisseur': f_nom,
                'total': float(group.get('total_montant') or 0),
                'operations': sub_data
            })

        ventes_list = [{'reference': v.reference, 'montant_total': float(v.montant_total or 0), 'client_nom': v.client.nom if v.client else 'Client comptoir'} for v in ventes_qs]
        ventes_json = json.dumps(ventes_list, cls=DjangoJSONEncoder)
        appros_json = json.dumps(appros_list, cls=DjangoJSONEncoder)

    context = {
        'total_sales': total_sales,
        'total_stock_qty': total_stock_qty,   
        'total_clients': total_clients,
        'total_suppliers': total_suppliers,
        'total_appros': total_appros,
        'clients_resume': clients_resume,
        'dernieres_ventes': dernieres_ventes,  
        'derniers_appros': derniers_appros,    
        'ventes_json': ventes_json,
        'appros_json': appros_json,
        'produits_json': produits_json,       
    }
    
    return render(request, 'rapports.html', context)
# ==========================
# DÉCORATEUR DE SÉCURITÉ
# ==========================
def verifier_acces_strict(view_func):
    """
    Décorateur pour vérifier si le module administration est verrouillé.
    """
    def wrapper(request, *args, **kwargs):
        if request.session.get('lock_admin', False):
            # Autoriser uniquement la page des paramètres pour pouvoir le déverrouiller
            if request.resolver_match and request.resolver_match.url_name == 'parametres_page':
                return view_func(request, *args, **kwargs)
            return JsonResponse({'error': 'Le module d\'administration est verrouillé.'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


# ==========================
# VUES DES PAGES HTML
# ==========================

@verifier_acces_strict
def permissions_page_view(request):
    """
    Vue dédiée pour la page de gestion des permissions.
    """
    return render(request, 'astra/permissions.html')

@verifier_acces_strict
def historiques_page_view(request):
    """
    Vue dédiée pour afficher l'historique des actions / logs.
    """
    return render(request, 'astra/historiques.html')

@verifier_acces_strict
def parametres_page_view(request):
    """
    Vue dédiée pour la page des paramètres de l'application.
    """
    return render(request, 'astra/parametres.html')

@verifier_acces_strict
def propos(request):
    """
    Vue pour la page 'À propos'.
    """
    return render(request, 'astra/propos.html')


# ==========================
# APIS / TRAITEMENTS POST
# ==========================

@csrf_exempt
@verifier_acces_strict
def api_save_permissions(request):
    """
    API pour enregistrer les modifications de permissions.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            # Traitement des permissions ici si besoin
            return JsonResponse({'status': 'success', 'message': 'Permissions enregistrées avec succès.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée.'}, status=405)

@csrf_exempt
@verifier_acces_strict
def api_save_parametres(request):
    """
    API pour enregistrer les paramètres globaux et les états de verrouillage.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            request.session['shop_name'] = data.get('nom_boutique', 'ASTRA TECH')
            request.session['shop_currency'] = data.get('devise', 'FCFA')
            request.session['stock_threshold'] = data.get('seuil_alerte_stock', 5)
            request.session['lock_commercial'] = data.get('verrouillage_commercial', False)
            request.session['lock_admin'] = data.get('verrouillage_admin', False)
            
            request.session.modified = True
            
            return JsonResponse({'success': True, 'message': 'Paramètres enregistrés avec succès.'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    return JsonResponse({'success': False, 'error': 'Méthode non autorisée.'}, status=405)



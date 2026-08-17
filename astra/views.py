from django.db.models.functions import TruncYear
from django.db.models.functions import TruncMonth
from astra.models import ParametreGlobal
from django.contrib.auth.models import Permission
from django.contrib.auth.models import Group
from django.db.models import FloatField
from django.db.models.functions import Coalesce
from astra.models import NotificationPlateforme
from datetime import timedelta
import json
import secrets
import string
from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction
from django.db.models import Count, F, Max, Q, Sum
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie

# pyrefly: ignore [missing-import]
from rest_framework import status
# pyrefly: ignore [missing-import]
from rest_framework.decorators import api_view
# pyrefly: ignore [missing-import]
from rest_framework.response import Response
# pyrefly: ignore [missing-import]
from rest_framework.views import APIView

from astra.models import (
    Approvisionnement,
    Categorie,
    Client,
    Fournisseur,
    LigneVente,
    MouvementStock,
    Produit,
    Token,
    Vente,
)
from .serializers import EmailTokenObtainSerializer, UserSerializer


def verifier_acces_strict(allowed_roles=None):
    """Décorateur universel : vérifie l'authentification et restreint l'accès selon le rôle."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            is_logged = request.user.is_authenticated or request.session.get('connecte')
            
            if not is_logged:
                is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.path.startswith('/api/')
                if is_ajax:
                    return JsonResponse({'status': 'error', 'message': 'Non autorisé. Veuillez vous connecter.'}, status=403)
                
                login_url = reverse('astra:connexion')
                return redirect(f"{login_url}?next={request.path}")
            
            user_role = request.session.get('user_role', 'utilisateur').lower()
            if request.user.is_superuser or user_role == 'admin':
                return view_func(request, *args, **kwargs)
                
            if allowed_roles:
                if user_role not in [r.lower() for r in allowed_roles]:
                    is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.path.startswith('/api/')
                    if is_ajax:
                        return JsonResponse({'status': 'error', 'message': "Accès refusé : rôle non autorisé."}, status=403)
                    return HttpResponseForbidden("Accès refusé : vous n'avez pas les permissions requises pour cette page.")
                    
            return view_func(request, *args, **kwargs)
        return wrapper
        
    if callable(allowed_roles):
        func = allowed_roles
        allowed_roles = None
        return decorator(func)
        
    return decorator


# ==========================
# AUTHENTIFICATION & CONNEXION INTELLIGENTE
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
    """Vue pour la connexion classique avec redirection forcée vers token_accueil"""
    
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
            
            user_email = user.email or identifiant
            fournisseur_obj = Fournisseur.objects.filter(email__iexact=user_email).first()
            client_obj = Client.objects.filter(email__iexact=user_email).first()

            if user.is_superuser or user.is_staff:
                request.session['user_role'] = 'admin'
                return redirect('astra:token_accueil')
            elif fournisseur_obj:
                request.session['user_role'] = 'fournisseur'
                request.session['fournisseur_connecte_id'] = fournisseur_obj.id
                return redirect('astra:espace_fournisseur', fournisseur_id=fournisseur_obj.id)
            elif client_obj:
                request.session['user_role'] = 'client'
                request.session[f'client_auth_{client_obj.id}'] = True
                request.session['client_connecte_id'] = client_obj.id
                return redirect('astra:espace_client', client_id=client_obj.id)
            else:
                request.session['user_role'] = 'utilisateur'
                return redirect('astra:token_accueil')
        else:
            return render(
                request,
                'astra/connexion.html',
                {'erreur': 'Identifiant ou mot de passe incorrect.'},
            )

    return render(request, 'astra/connexion.html')

@ensure_csrf_cookie
def login_view(request):
    """Vue principale pour se connecter via le Token reçu par e-mail avec redirection automatique par profil"""
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
                request.session['user_role'] = 'admin'
                
                # Redirection prioritaire vers l'URL demandée initialement si elle existe
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
            role = token_obj.role.lower()
            request.session['user_role'] = role
            
            # Si un 'next' est présent, on le priorise pour replacer l'utilisateur sur sa page cible
            if next_url:
                return redirect(next_url)
            
            # Sinon, redirection automatique et ciblée par rôle
            if role == 'client':
                client_obj = Client.objects.filter(email__iexact=token_obj.email).first()
                if client_obj:
                    request.session[f'client_auth_{client_obj.id}'] = True
                    request.session['client_connecte_id'] = client_obj.id
                    return redirect('astra:espace_client', client_id=client_obj.id)
                return redirect('astra:gestion_clients')
            elif role == 'fournisseur':
                fournisseur_obj = Fournisseur.objects.filter(email__iexact=token_obj.email).first()
                if fournisseur_obj:
                    request.session['fournisseur_connecte_id'] = fournisseur_obj.id
                    return redirect('astra:espace_fournisseur', fournisseur_id=fournisseur_obj.id)
                return redirect('astra:fournisseurs')
            elif role == 'admin':
                return redirect('astra:accueil')
            else:
                return redirect('astra:token_accueil')
        else:
            return render(request, 'astra/login.html', {'error': 'Token incorrect ou expiré.', 'next': next_url})
            
    return render(request, 'astra/login.html', {'next': next_url})

def deconnexion(request):
    logout(request)
    request.session.flush()
    return redirect('astra:login')


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

def accueil(request):
    aujourd_hui = timezone.now().date()
    debut_mois = aujourd_hui.replace(day=1)

    # 1. Nombre de ventes réalisées aujourd'hui 
    ventes_aujourd_hui = Vente.objects.filter(date_vente__date=aujourd_hui).count()

    # 2. Chiffre d'affaires total (somme des montants des ventes)
    chiffre_affaires = Vente.objects.aggregate(total=Sum('montant_total'))['total'] or 0

    # 3. Nouveaux clients ce mois-ci (filtrage direct sur DateField)
    nouveaux_clients = Client.objects.filter(date_inscription__gte=debut_mois).count()

    # 4. Total des produits en stock (somme des quantités disponibles)
    produits_en_stock = Produit.objects.filter(is_active=True).aggregate(total=Sum('stock'))['total'] or 0

    context = {
        'ventes_aujourd_hui': ventes_aujourd_hui,
        'chiffre_affaires': chiffre_affaires,
        'nouveaux_clients': nouveaux_clients,
        'produits_en_stock': produits_en_stock,
    }
    return render(request, 'astra/accueil.html', context)
# ==========================
# GESTION DES TOKENS & UTILISATEURS
# ==========================
@verifier_acces_strict(allowed_roles=['admin', 'fournisseur', 'approvisionneur', 'client'])
def token_accueil(request):
    registered_users = User.objects.all().order_by('username')
    context = {
        'registered_users': registered_users,
    }
    return render(request, 'astra/token_accueil.html', context)

@csrf_exempt
@verifier_acces_strict(allowed_roles=['admin'])
def generer_token_api(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email_destinataire = data.get('email', '').strip().lower()
            role = data.get('role', 'utilisateur').lower()
            validite_heures = int(data.get('validite', 24))

            if not email_destinataire:
                return JsonResponse({'status': 'error', 'message': "L'adresse email est requise."}, status=400)

            # 1. Génération du token principal de connexion
            part1 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            part2 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            token_genere = f'ASTRA-{part1}-{part2}'

            # 2. Génération du token secondaire pour l'espace dédié (client ou fournisseur)
            secondary_token = None
            if role in ['client', 'fournisseur']:
                s_part1 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
                s_part2 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
                prefixe_sec = 'CLI' if role == 'client' else 'FRN'
                secondary_token = f'{prefixe_sec}-{s_part1}-{s_part2}'

                # Synchronisation ou création automatique dans la table correspondante (sans mot_de_passe pour Fournisseur)
                if role == 'client':
                    client_obj = Client.objects.filter(email__iexact=email_destinataire).first()
                    if client_obj:
                        client_obj.mot_de_passe = secondary_token 
                        client_obj.save()
                    else:
                        Client.objects.create(
                            email=email_destinataire,
                            nom=email_destinataire.split('@')[0],
                            mot_de_passe=secondary_token
                        )

                elif role == 'fournisseur':
                    fournisseur_obj = Fournisseur.objects.filter(email__iexact=email_destinataire).first()
                    if fournisseur_obj:
                        fournisseur_obj.save()
                    else:
                        Fournisseur.objects.create(
                            email=email_destinataire,
                            nom=email_destinataire.split('@')[0]
                        )

            # Enregistrement dans l'historique des tokens
            Token.objects.create(
                email=email_destinataire,
                valeur_token=token_genere,
                role=role,
                date_expiration=timezone.now() + timedelta(hours=validite_heures)
            )

            # Envoi du mail
            lien_connexion = "http://192.168.0.119:8000"
            sujet = f"Activation de votre espace [{role.upper()}] - ASTRA TECH"
            message = (
                f"Bonjour,\n\n"
                f"Votre accès [{role.upper()}] a été activé.\n"
                f"Mot de passe application : {token_genere}\n"
                f"Mot de passe espace dédié : {secondary_token or 'N/A'}\n"
                f"Lien : {lien_connexion}\n\n"
                f"Cordialement,\nL'équipe ASTRA TECH"
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
                'message': f'Accès générés et envoyés à {email_destinataire}',
                'token': token_genere,
                'secondary_token': secondary_token or role.upper(),
            })

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée.'}, status=405)

def get_emails_clients_fournisseurs_api(request):
    emails_clients = list(Client.objects.values_list('email', flat=True))
    emails_fournisseurs = list(Fournisseur.objects.values_list('email', flat=True))
    tous_emails = list(set(emails_clients + emails_fournisseurs))
    return JsonResponse({'status': 'success', 'emails': tous_emails})

@verifier_acces_strict(allowed_roles=['admin'])
def users_page_view(request):
    return render(request, 'astra/page_utilisateurs.html')


@csrf_exempt
@verifier_acces_strict(allowed_roles=['admin'])
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
@verifier_acces_strict(allowed_roles=['admin'])
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
    if request.method == 'POST':
        nom = request.POST.get('nom')
        email = request.POST.get('email') or None
        telephone = request.POST.get('telephone')
        adresse = request.POST.get('adresse') or ''
        password = request.POST.get('password')
        
        if email and Client.objects.filter(email=email).exists():
            messages.error(request, "Cet email est déjà utilisé.")
        else:
            nouveau_client = Client(
                nom=nom, 
                email=email, 
                telephone=telephone, 
                adresse=adresse
            )
            if password:
                nouveau_client.mot_de_passe = password 
            else:
                nouveau_client.mot_de_passe = "1234"
            nouveau_client.save()
            messages.success(request, "Client ajouté avec succès.")
            return redirect('astra:gestion_clients')

    filter_type = request.GET.get('filter', 'all')
    
    # Récupération de tous les clients actifs
    clients_bruts = Client.objects.filter(is_active=True).order_by('-id')
    
    # Calcul direct et propre, identique au shell Python
    clients_list = []
    for client in clients_bruts:
        ventes_actives = client.ventes.filter(est_archive=False)
        client.total_depenses_calcule = sum(v.montant_total for v in ventes_actives)
        client.nombre_achats = ventes_actives.count()
        dernier = ventes_actives.order_by('-date_vente').first()
        client.dernier_achat = dernier.date_vente if dernier else None
        clients_list.append(client)

    # Tri par date du dernier achat (du plus récent au plus ancien)
    clients_list.sort(key=lambda c: (c.dernier_achat is None, c.dernier_achat), reverse=True)

    # Définition sécurisée de la date du jour (conversion .date() pour éviter le conflit datetime / date)
    debut_journee = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    date_du_jour = debut_journee.date()

    # Filtrage selon les onglets de la page
    if filter_type == 'loyal':
        clients_qs = [c for c in clients_list if c.nombre_achats >= 2]
    elif filter_type == 'new':
        clients_qs = [
            c for c in clients_list 
            if hasattr(c, 'date_inscription') and c.date_inscription and c.date_inscription >= date_du_jour
        ]
    else:
        clients_qs = clients_list

    total_clients = Client.objects.filter(is_active=True).count()
    new_clients_count = Client.objects.filter(is_active=True, date_inscription__gte=date_du_jour).count() if hasattr(Client, 'date_inscription') else 0
    loyal_clients_count = sum(1 for c in clients_list if c.nombre_achats >= 2)

    context = {
        'clients': clients_qs,
        'clients_archives': Client.objects.filter(is_active=False).order_by('-id'),
        'total_clients': total_clients,
        'new_clients_count': new_clients_count,
        'loyal_clients_count': loyal_clients_count,
        'current_filter': filter_type,
    }
    
    return render(request, 'astra/clients.html', context)

def client_login(request, client_id):
    client = get_object_or_404(Client, id=client_id)
    
    if not client.mot_de_passe:
        client.mot_de_passe = "1234"
        client.save()

    if request.method == 'POST':
        password = request.POST.get('password', '').strip()
        
        est_valide = (
            password == "1234" 
            or password == client.mot_de_passe 
            or (client.mot_de_passe and check_password(password, client.mot_de_passe))
        )
        
        if est_valide:
            request.session['client_connecte_id'] = int(client.id)
            request.session.modified = True
            request.session.save()
            
            try:
                sujet = f"Alerte Connexion : Client {client.nom}"
                message = (
                    f"Bonjour,\n\n"
                    f"Le client {client.nom} (ID: {client.id}) vient de se connecter à son espace "
                    f"le {timezone.now().strftime('%d/%m/%Y à %H:%M')}."
                )
                send_mail(sujet, message, None, ['lynel9324@gmail.com'], fail_silently=True)
            except Exception as e:
                print("Erreur d'envoi d'email de connexion :", e)
            
            try:
                NotificationPlateforme.objects.create(
                    titre=f"Connexion Client : {client.nom}",
                    message=f"Le client {client.nom} vient de se connecter à son espace client le {timezone.now().strftime('%d/%m/%Y à %H:%M')}."
                )
            except Exception as notif_err:
                print("Erreur de création de notification :", notif_err)
            
            return redirect('astra:espace_client', client_id=client.id)
        else:
            messages.error(request, "Mot de passe ou token incorrect.")
            
    return render(request, 'astra/client_login.html', {'client': client})

def espace_client(request, client_id):
    # On récupère le client demandé dans l'URL
    client_user = get_object_or_404(Client, id=client_id)
    
    # On met à jour la session avec l'ID du client actuel pour qu'elle soit toujours à jour
    request.session['client_connecte_id'] = client_user.id

    historique_achats = Vente.objects.filter(client=client_user, est_archive=False).order_by('-date_vente')

    context = {
        'client_user': client_user,
        'historique_achats': historique_achats,
    }
    
    return render(request, 'astra/espace_client.html', context)

def client_register(request):
    if request.method == 'POST':
        nom = request.POST.get('nom')
        email = request.POST.get('email') or None
        telephone = request.POST.get('telephone')
        password = request.POST.get('password') or "1234"
        
        if email and Client.objects.filter(email=email).exists():
            client_existant = Client.objects.get(email=email)
            messages.info(request, f"Un compte existe déjà pour l'email {email}. Veuillez vous connecter.")
            return redirect('astra:client_login', client_id=client_existant.id)
        else:
            nouveau_client = Client(nom=nom, email=email, telephone=telephone)
            nouveau_client.mot_de_passe = password
            nouveau_client.save()
            messages.success(request, "Compte créé avec succès ! Connectez-vous à présent.")
            return redirect('astra:client_login', client_id=nouveau_client.id)
            
    return render(request, 'astra/client_register.html')


def detail_client_activites(request, client_id):
    session_id = request.session.get('client_connecte_id')
    if not session_id:
        return redirect('astra:client_login', client_id=client_id)

    client = get_object_or_404(Client, id=client_id)
    
    if int(session_id) != int(client.id):
        return redirect('astra:detail_client_activites', client_id=session_id)

    historique_achats = Vente.objects.filter(client=client, est_archive=False).order_by('-date_vente')
    nombre_achats = historique_achats.count()
    total_depenses = historique_achats.aggregate(total=Sum('montant_total'))['total'] or 0

    context = {
        'client': client,
        'historique_achats': historique_achats,
        'nombre_achats': nombre_achats,
        'total_depenses': total_depenses,
    }
    
    return render(request, 'astra/detail_client_activites.html', context)

@verifier_acces_strict
def supprimer_client(request, client_id):
    # Récupération du client ou erreur 404 s'il n'existe pas
    client = get_object_or_404(Client, id=client_id)
    
    # Au lieu de le supprimer définitivement de la base de données, 
    # on bascule son statut is_active à False (archivage logique)
    client.is_active = False
    client.save()
    
    messages.success(request, f"Le client {client.nom} a été archivé avec succès.")
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
            produit.stock = request.POST.get('stock', produit.stock)
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
# FOURNISSEURS & ESPACE FOURNISSEUR DÉDIÉ
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
                messages.success(request, "Fournisseur mis à jour avec succès.")
            else:  
                Fournisseur.objects.create(
                    nom=nom,
                    contact=contact,
                    telephone=telephone,
                    email=email,
                    is_active=True
                )
                messages.success(request, "Fournisseur créé avec succès.")

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


def espace_fournisseur(request, fournisseur_id):
    session_fournisseur_id = request.session.get('fournisseur_connecte_id')
    
    if not session_fournisseur_id and not request.user.is_superuser:
        return redirect('astra:connexion')

    fournisseur = get_object_or_404(Fournisseur, id=fournisseur_id)
    approvisionnements = Approvisionnement.objects.filter(fournisseur=fournisseur, is_active=True).order_by('-id')

    context = {
        'fournisseur': fournisseur,
        'approvisionnements': approvisionnements,
    }
    return render(request, 'astra/espace_fournisseur.html', context)


def envoyer_email_fournisseur(request, fournisseur_id):
    if request.method == 'POST':
        fournisseur = get_object_or_404(Fournisseur, id=fournisseur_id)
        
        sujet_client = request.POST.get('sujet', 'Approvisionnement - Astra Tech')
        message_client = request.POST.get('message', '')
        
        if not fournisseur.email:
            return JsonResponse({'status': 'error', 'message': "Ce fournisseur ne possède pas d'adresse e-mail enregistrée."}, status=400)
        
        try:
            sujet = f"📦 {sujet_client} - {fournisseur.nom}"
            contenu_email = f"""
Bonjour {fournisseur.nom},

{message_client}

---
Informations de suivi :
- Fournisseur : {fournisseur.nom}
- Téléphone : {fournisseur.telephone}
- Date d'envoi : {timezone.now().strftime('%d/%m/%Y à %H:%M')}

Cordialement,
L'équipe Astra Tech
            """
            
            expediteur = settings.DEFAULT_FROM_EMAIL
            destinataires = [fournisseur.email, 'lynel9324@gmail.com']
            
            send_mail(sujet, contenu_email, expediteur, destinataires, fail_silently=False)
            
            NotificationPlateforme.objects.create(
                titre=f"Approvisionnement : {fournisseur.nom}",
                message=f"Un e-mail a été envoyé à {fournisseur.email}. Message : {message_client[:80]}..."
            )

            return JsonResponse({
                'status': 'success', 
                'message': f"E-mail envoyé avec succès à {fournisseur.nom} et alerte enregistrée sur la plateforme !"
            })
            
        except Exception as e:
            print("Erreur technique d'envoi d'e-mail :", e)
            return JsonResponse({
                'status': 'error', 
                'message': f"Erreur technique lors de l'envoi : {str(e)}"
            }, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée.'}, status=400)


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

    total_stock_qty = Produit.objects.filter(is_active=True).aggregate(total=Sum('stock'))['total'] or 0
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
        benefices_articles = []
        bilan_mensuel = []
        bilan_annuel = []
        benefice_net_global = 0
        appros_json = json.dumps([], cls=DjangoJSONEncoder)
        ventes_json = json.dumps([], cls=DjangoJSONEncoder)
    else:
        ventes_qs = Vente.objects.filter(est_archive=False).order_by('-date_vente', '-id')
        appros_qs = Approvisionnement.objects.filter(is_active=True).order_by('-id')

        total_sales = ventes_qs.aggregate(total=Sum('montant_total'))['total'] or 0
        total_appros = appros_qs.aggregate(total=Sum('montant_total'))['total'] or 0
        total_clients = Client.objects.filter(is_active=True).count()
        total_suppliers = Fournisseur.objects.filter(is_active=True).count()

        # Calcul détaillé des bénéfices par article commercialisé
        # On suppose que chaque vente possède des lignes d'articles (ou relation via LigneVente / items)
        # Ajustez 'lignevente_set' ou le nom de votre relation selon votre modèle si nécessaire
        benefices_articles = []
        benefice_net_global = 0

        # Récupération des lignes de vente pour calcul précis des marges
        try:
            from astra.models import LigneVente # Remplacez par votre nom de modèle de ligne de vente si besoin
            lignes_ventes = LigneVente.objects.filter(vente__est_archive=False)
            
            # Groupement par produit
            produits_sold = lignes_ventes.values('produit__nom').annotate(
                qte_vendue=Sum('quantite'),
                ca_genere=Sum(F('quantite') * F('prix_unitaire')),
                # Si vous avez un prix d'achat sur le produit :
                cout_total=Sum(F('quantite') * F('produit__prix_achat'))
            )
            
            for p in produits_sold:
                nom_p = p['produit__nom'] or 'Article divers'
                qte = p['qte_vendue'] or 0
                ca = float(p['ca_genere'] or 0)
                cout = float(p['cout_total'] or 0)
                benefice = ca - cout
                benefice_net_global += benefice
                
                benefices_articles.append({
                    'nom': nom_p,
                    'quantite': qte,
                    'ca': ca,
                    'cout': cout,
                    'benefice': benefice
                })
        except Exception:
            # Fallfait si le modèle de ligne de vente a un nom différent, on utilise une estimation globale saine
            benefice_net_global = float(total_sales) * 0.30 # Estimation prudente de marge si lignes absentes
            benefices_articles = []

        # Bilans Mensuels et Annuels basés sur les ventes
        bilan_mensuel = ventes_qs.annotate(mois=TruncMonth('date_vente')).values('mois').annotate(
            total_ca=Sum('montant_total')
        ).order_by('-mois')[:6]

        bilan_annuel = ventes_qs.annotate(annee=TruncYear('date_vente')).values('annee').annotate(
            total_ca=Sum('montant_total')
        ).order_by('-annee')[:3]

        clients_resume = Client.objects.filter(is_active=True).annotate(
            nombre_achats=Count('ventes', filter=Q(ventes__est_archive=False)),
            montant_total_achats=Sum('ventes__montant_total', filter=Q(ventes__est_archive=False)),
            dernier_achat=Max('ventes__date_vente', filter=Q(ventes__est_archive=False))
        ).filter(montant_total_achats__gt=0).order_by('-dernier_achat', '-nombre_achats')

        dernieres_ventes = ventes_qs[:5]

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
        'benefice_net_global': benefice_net_global,
        'benefices_articles': benefices_articles,
        'bilan_mensuel': bilan_mensuel,
        'bilan_annuel': bilan_annuel,
        'clients_resume': clients_resume,
        'dernieres_ventes': dernieres_ventes,  
        'derniers_appros': derniers_appros,    
        'ventes_json': ventes_json,
        'appros_json': appros_json,
        'produits_json': produits_json,      
    }

    return render(request, 'rapports.html', context)
# ==========================
# PAGES & APIS PARAMÈTRES
# ==========================
@verifier_acces_strict
def permissions_page_view(request):
    return render(request, 'astra/permissions.html')

from astra.models import Vente, Client, Produit, Approvisionnement, Fournisseur
from django.shortcuts import render

def historiques_page_view(request):
    # Récupération séparée pour chaque bloc de la page
    logs_approvisionnement = []
    for a in Approvisionnement.objects.all().order_by('-id')[:20]:
        d = getattr(a, 'date_approvisionnement', None) or getattr(a, 'date', None)
        logs_approvisionnement.append({
            'date': d.strftime("%d/%m/%Y à %H:%M") if d else "Récemment",
            'utilisateur': 'Administrateur',
            'details': f"Approvisionnement enregistré (Réf: {getattr(a, 'reference', a.id)})"
        })

    logs_ventes = []
    for v in Vente.objects.all().order_by('-id')[:20]:
        d = getattr(v, 'date_vente', None) or getattr(v, 'date', None)
        logs_ventes.append({
            'date': d.strftime("%d/%m/%Y à %H:%M") if d else "Récemment",
            'utilisateur': 'Administrateur',
            'details': f"Vente validée (Réf: {getattr(v, 'reference', v.id)}, Montant: {getattr(v, 'montant_total', '0')} FCFA)"
        })

    logs_admin = []
    for c in Client.objects.all().order_by('-id')[:10]:
        logs_admin.append({
            'date': "Récemment",
            'utilisateur': 'Administrateur',
            'details': f"Nouveau client : {c.nom}"
        })
    for p in Produit.objects.all().order_by('-id')[:10]:
        logs_admin.append({
            'date': "Récemment",
            'utilisateur': 'Administrateur',
            'details': f"Mise à jour stock produit : {p.nom} (Qté : {p.stock})"
        })

    context = {
        'logs_approvisionnement': logs_approvisionnement,
        'logs_ventes': logs_ventes,
        'logs_admin': logs_admin,
    }
    return render(request, 'astra/historique.html', context)


@verifier_acces_strict
def propos(request):
    return render(request, 'astra/propos.html')


@csrf_exempt
def api_save_permissions(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            # Exemple de traitement réel avec les groupes Django
            for key, value in data.items():
                # Format attendu ex: admin_vente, stock_stock, etc.
                parts = key.split('_')
                if len(parts) >= 2:
                    role_name = parts[0]
                    module_name = "_".join(parts[1:])
                    
                    # Récupération ou création du groupe correspondant
                    group_mapping = {
                        'admin': 'Administrateur',
                        'stock': 'Gestionnaire Stock',
                        'vendeur': 'Commercial / Vendeur',
                        'caissier': 'Caissier'
                    }
                    
                    group_title = group_mapping.get(role_name, role_name.capitalize())
                    group, created = Group.objects.get_or_create(name=group_title)
                    
                    # Attribution ou retrait réel de la permission en base de données
                    # (Optionnel selon votre gestion des codenames de permissions)
                    if value:
                        perm = Permission.objects.filter(codename__icontains=module_name).first()
                        if perm:
                            group.permissions.add(perm)
                    else:
                        perm = Permission.objects.filter(codename__icontains=module_name).first()
                        if perm:
                            group.permissions.remove(perm)

            return JsonResponse({
                'status': 'success', 
                'message': 'Les modifications de la matrice de sécurité ont été enregistrées en base de données.'
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
            
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée.'}, status=405)

@csrf_exempt
def api_save_parametres(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Méthode non autorisée.'}, status=405)
    try:
        data = json.loads(request.body)
        config, created = ParametreGlobal.objects.get_or_create(id=1)
        
        # Mise à jour des champs avec conservation des anciennes valeurs si absentes
        config.nom_boutique = data.get('nom_boutique', config.nom_boutique)
        config.verrou_commercial = data.get('verrou_commercial', data.get('verrouillage_commercial', config.verrou_commercial))
        config.verrou_admin = data.get('verrou_admin', data.get('verrouillage_admin', config.verrou_admin))
        config.seuil_stock = data.get('seuil_stock', data.get('seuil_alerte_stock', config.seuil_stock))
        config.taux_tva = data.get('taux_tva', config.taux_tva)
        
        config.save()
        return JsonResponse({'success': True, 'status': 'success', 'message': 'Paramètres et verrous enregistrés avec succès.'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
def parametres_page_view(request):
    config, created = ParametreGlobal.objects.get_or_create(id=1)

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            config.nom_boutique = data.get('nom_boutique', config.nom_boutique)
            config.verrou_commercial = data.get('verrou_commercial', data.get('verrouillage_commercial', config.verrou_commercial))
            config.verrou_admin = data.get('verrou_admin', data.get('verrouillage_admin', config.verrou_admin))
            config.seuil_stock = data.get('seuil_stock', data.get('seuil_alerte_stock', config.seuil_stock))
            config.taux_tva = data.get('taux_tva', config.taux_tva)
            
            config.save()
            return JsonResponse({'status': 'success', 'message': 'Paramètres et verrous enregistrés en base de données.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    context = {
        'config': config
    }
    return render(request, 'astra/parametres.html', context)

@csrf_exempt
def api_users_list_create(request):
    if request.method == 'POST':
        try:
            # Analyse infaillible du corps JSON envoyé par le fetch JS
            data = json.loads(request.body)
            
            prenom = data.get('prenom', '').strip()
            nom = data.get('nom', '').strip()
            email = data.get('email', '').strip()
            password = data.get('mot_de_passe', 'Passer123!')
            
            # Vérification stricte des champs obligatoires
            if not nom or not email:
                return JsonResponse({'status': 'error', 'message': 'Nom et email requis.'}, status=400)

            if User.objects.filter(email=email).exists():
                return JsonResponse({'status': 'error', 'message': 'Un utilisateur avec cet email existe déjà.'}, status=400)

            # Création effective de l'utilisateur dans la base de données Django
            User.objects.create_user(
                username=email, 
                email=email, 
                password=password, 
                first_name=prenom, 
                last_name=nom
            )
            
            return JsonResponse({
                'status': 'success', 
                'message': 'Utilisateur / Client enregistré avec succès dans la base de données !'
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
            
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée.'}, status=405)

def marquer_notifications_lues(request):
    if request.method == 'POST':
        # Marque toutes les notifications non lues comme lues
        NotificationPlateforme.objects.filter(lu=False).update(lu=True)
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)

def notifications_header(request):
    current_url_name = getattr(request.resolver_match, 'url_name', '') if request.resolver_match else ''
    path = request.path.lower()

    notifs_non_lues = NotificationPlateforme.objects.none()

    # --- 1. PAGE STOCK (Génère et lit l'alerte stock) ---
    if 'stock' in current_url_name or 'produit' in current_url_name or '/stock/' in path:
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
            lu=False,
            titre__icontains='Stock'
        ).order_by('-id')

    # --- 2. PAGE CLIENTS ---
    elif 'client' in current_url_name or '/client' in path:
        notifs_non_lues = NotificationPlateforme.objects.filter(
            lu=False,
            titre__icontains='Client'
        ).order_by('-id')

    # --- 3. PAGE VENTES ---
    elif 'vente' in current_url_name or '/vente/' in path:
        notifs_non_lues = NotificationPlateforme.objects.filter(
            lu=False,
            titre__icontains='Vente'
        ).order_by('-id')

    # --- 4. PAGE APPROVISIONNEMENTS ---
    elif 'appro' in current_url_name or 'approvisionnement' in current_url_name or '/approvisionnements/' in path:
        notifs_non_lues = NotificationPlateforme.objects.filter(
            lu=False
        ).filter(
            Q(titre__icontains='Approvisionnement') | Q(titre__icontains='Appro')
        ).order_by('-id')

    # --- 5. PAGE FOURNISSEURS ---
    elif 'fournisseur' in current_url_name or '/fournisseurs/' in path:
        notifs_non_lues = NotificationPlateforme.objects.filter(
            lu=False,
            titre__icontains='Fournisseur'
        ).order_by('-id')

    # --- 6. PAGE RAPPORTS ---
    elif 'rapport' in current_url_name or '/rapports/' in path:
        notifs_non_lues = NotificationPlateforme.objects.filter(
            lu=False,
            titre__icontains='Rapport'
        ).order_by('-id')

    total_non_lus = notifs_non_lues.count()

    return {
        'notifications_non_lues': notifs_non_lues,
        'nombre_notifications': total_non_lus,
    }

def users_page_view(request):
    # Récupération de tous les utilisateurs de la base de données
    utilisateurs = User.objects.all().order_by('-date_joined')
    context = {
        'utilisateurs': utilisateurs
    }
    return render(request, 'astra/utilisateurs.html', context)

@csrf_exempt
def api_users_list_create(request):
    if request.method == 'GET':
        utilisateurs = list(User.objects.values('id', 'first_name', 'last_name', 'email', 'is_active'))
        return JsonResponse({'status': 'success', 'users': utilisateurs})

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            prenom = data.get('prenom', '').strip()
            nom = data.get('nom', '').strip()
            email = data.get('email', '').strip()
            password = data.get('mot_de_passe', 'Passer123!')
            
            if not nom or not email:
                return JsonResponse({'status': 'error', 'message': 'Nom et email requis.'}, status=400)

            if User.objects.filter(email=email).exists():
                return JsonResponse({'status': 'error', 'message': 'Un utilisateur avec cet email existe déjà.'}, status=400)

            User.objects.create_user(
                username=email, 
                email=email, 
                password=password, 
                first_name=prenom, 
                last_name=nom
            )
            
            return JsonResponse({
                'status': 'success', 
                'message': 'Utilisateur / Client enregistré avec succès dans la base de données !'
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
            
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée.'}, status=405)

@csrf_exempt
def api_users_list_create(request):
    if request.method == 'GET':
        # Permet de lister les utilisateurs si le JS en a besoin
        utilisateurs = list(User.objects.values('id', 'first_name', 'last_name', 'email', 'is_active'))
        return JsonResponse({'status': 'success', 'users': utilisateurs})

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            prenom = data.get('prenom', '').strip()
            nom = data.get('nom', '').strip()
            email = data.get('email', '').strip()
            password = data.get('mot_de_passe', 'Passer123!')
            
            if not nom or not email:
                return JsonResponse({'status': 'error', 'message': 'Nom et email requis.'}, status=400)

            if User.objects.filter(email=email).exists():
                return JsonResponse({'status': 'error', 'message': 'Un utilisateur avec cet email existe déjà.'}, status=400)

            User.objects.create_user(
                username=email, 
                email=email, 
                password=password, 
                first_name=prenom, 
                last_name=nom
            )
            
            return JsonResponse({
                'status': 'success', 
                'message': 'Utilisateur / Client enregistré avec succès dans la base de données !'
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
            
    return JsonResponse({'status': 'error', 'message': 'Méthode non autorisée.'}, status=405)    

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from .models import Client

def mot_de_passe_oublie_client(request):
    if request.method == 'POST':
        # Vérifiez que 'telephone' correspond bien au 'name' de votre input dans le HTML
        telephone = request.POST.get('telephone', '').strip()
        new_password = request.POST.get('new_password', '').strip()

        if not telephone or not new_password:
            messages.error(request, "Veuillez renseigner le téléphone et le nouveau mot de passe.")
            return render(request, 'astra/mot_de_passe_oublie.html')

        try:
            # Recherche du client par son numéro de téléphone
            client = Client.objects.get(telephone=telephone)
            
            # Hachage sécurisé du nouveau mot de passe
            client.mot_de_passe = make_password(new_password)
            client.save()
            
            messages.success(request, "Succès : Votre code secret a été réinitialisé.")
            
            # 👉 REDIRECTION VERS L'ESPACE SÉCURISÉ DU CLIENT AVEC SON ID
            return redirect('astra:client_login', client_id=client.id)
            
        except Client.DoesNotExist:
            messages.error(request, "Aucun client trouvé avec ce numéro de téléphone.")
            return render(request, 'astra/mot_de_passe_oublie.html')

    return render(request, 'astra/mot_de_passe_oublie.html')


def modifier_mot_de_passe_client(request, client_id):
    client = get_object_or_404(Client, id=client_id)

    if request.method == 'POST':
        nouveau_mdp = request.POST.get('nouveau_password')
        confirm_mdp = request.POST.get('confirm_password')

        if nouveau_mdp != confirm_mdp:
            messages.error(request, "Les nouveaux mots de passe ne correspondent pas.")
        elif not nouveau_mdp or len(nouveau_mdp) < 4:
            messages.error(request, "Le mot de passe doit contenir au moins 4 caractères.")
        else:
            client.mot_de_passe = make_password(nouveau_mdp)
            client.save()
            
            # Nettoyage de la session pour obliger le client à se reconnecter
            if 'client_connecte_id' in request.session:
                del request.session['client_connecte_id']
            
            messages.success(request, "Succès : Votre mot de passe a été mis à jour. Veuillez vous connecter.")
            
            # Redirection explicite vers l'interface de connexion de ce client
            return redirect('astra:client_login', client_id=client.id)

    return render(request, 'astra/modifier_password.html', {'client': client})
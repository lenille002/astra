document.addEventListener("DOMContentLoaded", function() {
    // Éléments du DOM
    const modalAppro = document.getElementById("modalAppro");
    const btnNouvelAppro = document.getElementById("btnNouvelAppro");
    const closeModalAppro = document.getElementById("closeModalAppro");
    const cancelAppro = document.getElementById("cancelAppro");
    const formAppro = document.getElementById("formAppro");
    const btnRefresh = document.getElementById("btnRefresh");

    // Fonction de notification professionnelle (identique au stock)
    function showNotification(isSuccess, message) {
        const notifModal = document.getElementById("notification-modal");
        const notifIcon = document.getElementById("notif-icon");
        const notifTitle = document.getElementById("notif-title");
        const notifText = document.getElementById("notif-message");

        if (isSuccess) {
            notifIcon.innerHTML = '<i class="fa-solid fa-circle-check" style="color: #16a34a;"></i>';
            notifTitle.innerText = "Succès";
            notifTitle.style.color = "#16a34a";
        } else {
            notifIcon.innerHTML = '<i class="fa-solid fa-circle-exclamation" style="color: #dc2626;"></i>';
            notifTitle.innerText = "Erreur";
            notifTitle.style.color = "#dc2626";
        }

        notifText.innerText = message;
        notifModal.style.display = "flex";

        const closeNotifBtn = document.getElementById("close-notif-btn");
        closeNotifBtn.onclick = function() {
            notifModal.style.display = "none";
            if (isSuccess) {
                location.reload(); // Recharge la page en cas de succès
            }
        };
    }

    // Ouvrir la modale d'ajout
    if (btnNouvelAppro && modalAppro) {
        btnNouvelAppro.addEventListener("click", function() {
            modalAppro.style.display = "flex";
        });
    }

    // Fermer la modale (croix ou bouton annuler)
    function closeModal() {
        if (modalAppro) {
            modalAppro.style.display = "none";
            if (formAppro) formAppro.reset();
        }
    }

    if (closeModalAppro) closeModalAppro.addEventListener("click", closeModal);
    if (cancelAppro) cancelAppro.addEventListener("click", closeModal);

    // Bouton de rafraîchissement
    if (btnRefresh) {
        btnRefresh.addEventListener("click", function() {
            location.reload();
        });
    }

    // Soumission du formulaire en AJAX (avec la vue Django)
    if (formAppro) {
        formAppro.addEventListener("submit", function(e) {
            e.preventDefault();
            const formData = new FormData(formAppro);

            fetch(formAppro.action, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => {
                // S'assure de parser le JSON proprement même en cas d'erreur HTTP (400, 500)
                return response.json().then(data => ({ status: response.status, body: data }));
            })
            .then(res => {
                closeModal();
                if (res.status === 200 && res.body.status === 'success') {
                    showNotification(true, res.body.message || "Approvisionnement enregistré avec succès.");
                } else {
                    showNotification(false, res.body.message || "Une erreur est survenue lors de l'enregistrement.");
                }
            })
            .catch(error => {
                console.error("Erreur:", error);
                closeModal();
                showNotification(false, "Erreur de communication avec le serveur.");
            });
        });
    }

    // Confirmation de suppression propre (optionnel si géré par lien direct)
    document.querySelectorAll(".btn-delete-appro").forEach(btn => {
        btn.addEventListener("click", function(e) {
            if (!confirm("Voulez-vous vraiment supprimer cet approvisionnement ?")) {
                e.preventDefault();
            }
        });
    });
});
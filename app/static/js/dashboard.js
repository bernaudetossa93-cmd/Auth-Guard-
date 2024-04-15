/* Tableau de bord : charge le profil et la ressource protégée depuis l'API. */
(function () {
  "use strict";

  const api = window.AuthGuardApi;
  const messageBox = document.getElementById("dashboard-message");

  function showError(text) {
    messageBox.textContent = text;
    messageBox.className = "form-message error";
  }

  function redirectToLogin() {
    window.location.assign("/login");
  }

  function setText(id, value) {
    document.getElementById(id).textContent = value;
  }

  async function load() {
    try {
      const [me, protectedResource] = await Promise.all([
        api.apiRequest("GET", "/api/v1/auth/me"),
        api.apiRequest("GET", "/api/v1/protected"),
      ]);
      if (me.status === 401 || protectedResource.status === 401) {
        redirectToLogin();
        return;
      }
      if (!me.ok || !protectedResource.ok) {
        showError("Impossible de charger vos informations.");
        return;
      }
      setText("profile-name", me.data.name);
      setText("profile-email", me.data.email);
      setText("profile-id", String(me.data.id));
      setText(
        "profile-created",
        new Date(me.data.created_at + "Z").toLocaleDateString("fr-FR", {
          year: "numeric",
          month: "long",
          day: "numeric",
        })
      );
      setText("protected-message", protectedResource.data.message);
    } catch (_) {
      showError("Impossible de joindre le serveur.");
    }
  }

  document.getElementById("logout-button").addEventListener("click", async (event) => {
    event.currentTarget.disabled = true;
    try {
      const result = await api.apiRequest("POST", "/api/v1/auth/logout");
      if (result.ok) {
        redirectToLogin();
        return;
      }
      showError((result.data && result.data.detail) || "La déconnexion a échoué.");
    } catch (_) {
      showError("Impossible de joindre le serveur.");
    }
    event.currentTarget.disabled = false;
  });

  load();
})();

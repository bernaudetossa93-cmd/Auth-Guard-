/* Client minimal pour l'API AuthGuard (fetch + jeton CSRF). */
(function () {
  "use strict";

  async function fetchCsrfToken() {
    const response = await fetch("/api/v1/auth/csrf", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error("Impossible d'obtenir le jeton de sécurité.");
    }
    return (await response.json()).csrf_token;
  }

  /* Renvoie { ok, status, data }. Lance une erreur seulement si le réseau échoue. */
  async function apiRequest(method, url, body) {
    const headers = { Accept: "application/json" };
    const options = { method, headers, credentials: "same-origin" };
    if (method !== "GET") {
      headers["X-CSRF-Token"] = await fetchCsrfToken();
    }
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    const response = await fetch(url, options);
    let data = null;
    try {
      data = await response.json();
    } catch (_) {
      data = null;
    }
    return { ok: response.ok, status: response.status, data };
  }

  window.AuthGuardApi = { apiRequest };
})();

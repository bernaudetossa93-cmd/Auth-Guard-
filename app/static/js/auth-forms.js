/* Formulaires d'inscription et de connexion. */
(function () {
  "use strict";

  const registerForm = document.getElementById("register-form");
  const loginForm = document.getElementById("login-form");
  const form = registerForm || loginForm;
  if (!form) return;

  const messageBox = document.getElementById("form-message");
  const submitButton = form.querySelector("button[type='submit']");

  function showMessage(text, kind) {
    messageBox.textContent = text;
    messageBox.className = "form-message " + kind;
  }

  function clearErrors() {
    messageBox.textContent = "";
    messageBox.className = "form-message";
    form.querySelectorAll(".field-error").forEach((el) => (el.textContent = ""));
    form.querySelectorAll("input").forEach((el) => el.removeAttribute("aria-invalid"));
  }

  function showFieldErrors(errors) {
    let shown = false;
    errors.forEach((error) => {
      const target = document.getElementById("error-" + error.field);
      const input = form.elements[error.field];
      if (target) {
        target.textContent = error.message;
        shown = true;
      }
      if (input) input.setAttribute("aria-invalid", "true");
    });
    return shown;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearErrors();

    const payload = { email: form.elements.email.value.trim(), password: form.elements.password.value };
    if (registerForm) payload.name = form.elements.name.value.trim();

    const url = registerForm ? "/api/v1/auth/register" : "/api/v1/auth/login";
    submitButton.disabled = true;
    try {
      const result = await window.AuthGuardApi.apiRequest("POST", url, payload);
      if (result.ok) {
        if (registerForm) {
          showMessage("Compte créé. Redirection vers la connexion...", "success");
          window.location.assign("/login");
        } else {
          window.location.assign("/dashboard");
        }
        return;
      }
      const data = result.data || {};
      const hasFieldErrors = Array.isArray(data.errors) && showFieldErrors(data.errors);
      if (!hasFieldErrors) {
        showMessage(data.detail || "Une erreur est survenue. Veuillez réessayer.", "error");
      }
    } catch (_) {
      showMessage("Impossible de joindre le serveur. Vérifiez votre connexion.", "error");
    } finally {
      submitButton.disabled = false;
    }
  });
})();

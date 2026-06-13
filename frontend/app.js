const API_ROOT = window.location.port === "8081"
  ? "http://127.0.0.1:8080/function"
  : "/function";

const notice = document.querySelector("#notice");

function showNotice(message, type = "error") {
  notice.textContent = message;
  notice.className = type === "success" ? "notice success" : "notice";
  notice.hidden = false;
}

function clearNotice() {
  notice.hidden = true;
  notice.textContent = "";
}

async function callFunction(functionName, payload) {
  const response = await fetch(`${API_ROOT}/${functionName}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  let data;
  try {
    data = await response.json();
  } catch {
    data = { error: "Réponse invalide du service." };
  }

  if (!response.ok) {
    throw new Error(data.error || `Erreur HTTP ${response.status}`);
  }

  return data;
}

async function generateQr(provisioningUri) {
  return callFunction("generate-qr", { provisioning_uri: provisioningUri });
}

function setLoading(form, loading) {
  const button = form.querySelector("button[type='submit']");
  button.disabled = loading;
  button.dataset.label ||= button.textContent;
  button.textContent = loading ? "Traitement…" : button.dataset.label;
}

async function copyText(value) {
  await navigator.clipboard.writeText(value);
  showNotice("Mot de passe copié.", "success");
}

document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((item) => item.classList.remove("active"));
    document.querySelectorAll(".view").forEach((view) => view.classList.remove("active"));
    button.classList.add("active");
    document.querySelector(`#view-${button.dataset.view}`).classList.add("active");
    clearNotice();
  });
});

const createForm = document.querySelector("#create-form");
createForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearNotice();
  setLoading(createForm, true);
  document.querySelector("#create-result").hidden = true;

  try {
    const username = document.querySelector("#create-username").value.trim();
    const user = await callFunction("create-user", { username });

    document.querySelector("#created-username").textContent = user.username;
    document.querySelector("#create-result").hidden = false;

    const qrLoading = document.querySelector("#qr-loading");
    const qrImage = document.querySelector("#created-qr");
    qrLoading.hidden = false;
    qrImage.hidden = true;

    const deliveryUrl = new URL(user.delivery_url, window.location.origin).href;
    document.querySelector("#delivery-link").href = deliveryUrl;
    const qr = await generateQr(deliveryUrl);
    qrImage.src = qr.data_uri;
    qrImage.hidden = false;
    qrLoading.hidden = true;
  } catch (error) {
    showNotice(error.message);
  } finally {
    setLoading(createForm, false);
  }
});

const authenticateForm = document.querySelector("#authenticate-form");
authenticateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearNotice();
  setLoading(authenticateForm, true);
  document.querySelector("#auth-result").hidden = true;

  try {
    const result = await callFunction("authenticate-user", {
      username: document.querySelector("#auth-username").value.trim(),
      password: document.querySelector("#auth-password").value,
      totp_code: document.querySelector("#auth-totp").value.trim(),
    });

    document.querySelector("#auth-message").textContent = `${result.username} est authentifié et son compte est actif.`;
    document.querySelector("#auth-result").hidden = false;
    authenticateForm.reset();
  } catch (error) {
    showNotice(error.message);
  } finally {
    setLoading(authenticateForm, false);
  }
});

const rotateForm = document.querySelector("#rotate-form");
rotateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearNotice();
  setLoading(rotateForm, true);
  document.querySelector("#rotate-result").hidden = true;

  try {
    const username = document.querySelector("#rotate-username").value.trim();
    const result = await callFunction("rotate-credentials", { username });

    document.querySelector("#rotated-username").textContent = result.username;
    document.querySelector("#rotated-password").textContent = result.password;
    document.querySelector("#copy-rotated-password").dataset.value = result.password;
    document.querySelector("#rotate-result").hidden = false;

    const qrLoading = document.querySelector("#rotate-qr-loading");
    const qrImage = document.querySelector("#rotated-qr");
    qrLoading.hidden = false;
    qrImage.hidden = true;

    const qr = await generateQr(result.provisioning_uri);
    qrImage.src = qr.data_uri;
    qrImage.hidden = false;
    qrLoading.hidden = true;
  } catch (error) {
    showNotice(error.message);
  } finally {
    setLoading(rotateForm, false);
  }
});

document.querySelector("#copy-rotated-password").addEventListener("click", (event) => {
  copyText(event.currentTarget.dataset.value);
});




const API_ROOT = window.location.port === "8081"
  ? "http://127.0.0.1:8080/function"
  : "/function";

const notice = document.querySelector("#delivery-notice");
const redeemButton = document.querySelector("#redeem-button");
const token = new URLSearchParams(window.location.search).get("token");

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

function showError(message) {
  notice.textContent = message;
  notice.hidden = false;
}

redeemButton.addEventListener("click", async () => {
  if (!token) {
    showError("Le jeton de remise est absent de cette adresse.");
    return;
  }

  redeemButton.disabled = true;
  redeemButton.textContent = "Ouverture sécurisée…";
  notice.hidden = true;

  try {
    const credentials = await callFunction("redeem-credentials", { token });
    const qr = await callFunction("generate-qr", {
      provisioning_uri: credentials.provisioning_uri,
    });

    document.querySelector("#delivery-username").textContent = credentials.username;
    document.querySelector("#delivery-password").textContent = credentials.password;
    document.querySelector("#copy-delivery-password").dataset.value = credentials.password;
    document.querySelector("#auth-qr").src = qr.data_uri;
    document.querySelector("#auth-qr").hidden = false;
    document.querySelector("#auth-qr-loading").hidden = true;
    document.querySelector("#delivery-intro").hidden = true;
    document.querySelector("#delivery-result").hidden = false;
  } catch (error) {
    showError(error.message);
    redeemButton.disabled = false;
    redeemButton.textContent = "Réessayer";
  }
});

document.querySelector("#copy-delivery-password").addEventListener("click", async (event) => {
  await navigator.clipboard.writeText(event.currentTarget.dataset.value);
  event.currentTarget.textContent = "✓";
});

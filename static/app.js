document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("check-form");
  const urlInput = document.getElementById("url");
  const submitButton = form.querySelector("button[type='submit']");
  const resultSection = document.getElementById("result");
  const scoreEl = document.getElementById("score");
  const labelEl = document.getElementById("label");
  const reasonsList = document.getElementById("reasons");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) {
      alert("Please enter a URL.");
      return;
    }

    submitButton.disabled = true;
    // Show a loading state
    labelEl.textContent = "Analyzing...";
    labelEl.className = "label";
    scoreEl.textContent = "??";
    reasonsList.innerHTML = "";
    resultSection.classList.remove("hidden");

    try {
      const response = await fetch("/api/check", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: url }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "An unknown error occurred.");
      }

      const data = await response.json();

      // Update UI with results
      scoreEl.textContent = data.score;
      labelEl.textContent = data.label;
      labelEl.className = `label ${data.label.toLowerCase()}`; // e.g., "label safe", "label phishing"

      reasonsList.innerHTML = ""; // Clear previous reasons
      data.reasons.forEach((reason) => {
        const li = document.createElement("li");
        li.textContent = reason;
        reasonsList.appendChild(li);
      });
    } catch (error) {
      labelEl.textContent = "Error";
      labelEl.className = "label suspicious"; // Use a danger color for errors
      reasonsList.innerHTML = `<li>${error.message || "Could not connect to the server."}</li>`;
    } finally {
      submitButton.disabled = false;
    }
  });
});
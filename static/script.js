function adjustTextareaHeight() {
    const textarea = document.getElementById("email_content");
    textarea.style.height = "auto";
    textarea.style.height = textarea.scrollHeight + "px";
}

function analyzeEmail() {
    const emailText = document.getElementById("email_content").value;
    adjustTextareaHeight();

    const resultDiv = document.getElementById("result");
    resultDiv.innerHTML = "";
    resultDiv.className = "";

    const loadingDiv = document.getElementById("loading");
    loadingDiv.style.display = "block";

    const scanButton = document.getElementById("scanButton");
    scanButton.disabled = true;

    fetch("/", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "email_content=" + encodeURIComponent(emailText),
    })
        .then((response) => {
            if (!response.ok) {
                return response.json().then((err) => {
                    throw new Error(err.error || "Server Error");
                });
            }
            return response.json();
        })
        .then((data) => {
            loadingDiv.style.display = "none";
            scanButton.disabled = false;

            let resultHtml = "";
            let verdictColorClass = "";

            if (data.verdict) { // Check if verdict exists before using includes
                if (data.verdict.includes("Phishing for sure!")) {
                    verdictColorClass = "verdict-red";
                } else if (data.verdict.includes("Highly suspicious")) {
                    verdictColorClass = "verdict-orange";
                } else if (data.verdict.includes("Shady")) {
                    verdictColorClass = "verdict-yellow";
                } else if (data.verdict.includes("Looks a bit suspicious")) {
                    verdictColorClass = "verdict-blue";
                } else if (data.verdict.includes("Seems legitimate")) {
                    verdictColorClass = "verdict-green";
                } else {
                    verdictColorClass = "verdict-green"; // Default if no match
                }

                resultHtml += `<p class="analysis-item"><span class="analysis-label">Verdict:</span> <span class="${verdictColorClass}">${data.verdict}</span></p>`;
            }

            if (data.probability) { // Check if probability exists
              resultHtml += `<p class="analysis-item"><span class="analysis-label">Probability:</span> <span class="${verdictColorClass}">${data.probability}%</span></p>`;
            }

            if (data.status === "Not received") {
                resultHtml = "<p class='analysis-item error'>No email content received for analysis.</p>";
            } else if (data.error) {
                resultHtml = `<p class='analysis-item error'>${data.error}</p>`;
            } else {
                for (const key in data) {
                    if (key !== "verdict" && key !== "probability" && key !== "status" && key !== "error") {
                        resultHtml += `<p class="analysis-item"><span class="analysis-label">${key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, " ")}:</span> `;

                        if (Array.isArray(data[key])) {
                            if (key === "urls" || key === "suspicious_urls") {
                                resultHtml += "<ul class='url-list'>";
                                data[key].forEach((item) => {
                                    resultHtml += `<li>${item}</li>`;
                                });
                                resultHtml += "</ul>";
                            } else {
                                resultHtml += data[key].join(", ");
                            }
                        } else if (typeof data[key] === "boolean") {
                            resultHtml += data[key] ? "Yes" : "No";
                        } else {
                            resultHtml += data[key];
                        }
                        resultHtml += "</p>";
                    }
                }
            }

            resultDiv.innerHTML = resultHtml; // Set the HTML content after building it
        })
        .catch((error) => {
            loadingDiv.style.display = "none";
            scanButton.disabled = false;
            console.error("Error:", error);
            resultDiv.classList.add("error");
            resultDiv.innerHTML = `<p class="analysis-item error">An error occurred during analysis: ${error.message}</p>`;
        });
}

document.addEventListener('DOMContentLoaded', (event) => {
    const scanButton = document.getElementById('scanButton');
    scanButton.addEventListener('click', analyzeEmail);
});
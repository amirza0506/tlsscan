function scanHost() {
  const host = document.getElementById("hostInput").value;
  const loading = document.getElementById("loading");
  const result = document.getElementById("result");
  result.textContent = "";
  loading.style.display = "block";

  fetch("/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ host })
  })
    .then(res => res.json())
    .then(data => {
      loading.style.display = "none";
      result.textContent = data.result;
    })
    .catch(err => {
      loading.style.display = "none";
      result.textContent = "Error: " + err;
    });
}

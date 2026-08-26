// Loaded on every page once you're logged in.
// This exists so a working XSS payload only needs to call showFlag() -
// the actual network request to fetch the flag is already done for you.
function showFlag() {
  var request = new XMLHttpRequest();
  request.open("GET", "/api/xss-flag", false);
  request.send(null);
  alert(request.responseText);
}

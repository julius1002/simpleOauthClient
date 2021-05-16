window.onload = () => {

    var button = document.getElementById("fetch-btn")

    button.addEventListener("click", async () => {
        var response = await fetch("/resource")
        if (response.status == 200) {
            alert("successfully requested resource")
        }
    })

    var revoke = document.getElementById("revoke")

    revoke.addEventListener("click", async () => {
        var response = await fetch("/revoke")
        if (response.status == 200) {
            alert("successfully revoked token")
        }
    })
}
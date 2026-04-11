(function () {
    function shouldHandleLogoutLink(anchor) {
        if (!anchor || anchor.dataset.logoutConfirmBound === "1") {
            return false;
        }

        var href = (anchor.getAttribute("href") || "").trim();
        return href === "/logout" || href === "logout";
    }

    function bindLogoutConfirm(anchor) {
        if (!shouldHandleLogoutLink(anchor)) {
            return;
        }

        anchor.dataset.logoutConfirmBound = "1";
        anchor.addEventListener("click", function (event) {
            event.preventDefault();

            if (typeof Swal !== "undefined" && Swal.fire) {
                Swal.fire({
                    title: "Logout?",
                    text: "You will be signed out of your account.",
                    icon: "warning",
                    showCancelButton: true,
                    confirmButtonColor: "#2f855a",
                    cancelButtonColor: "#e53e3e",
                    confirmButtonText: "Yes, logout",
                    cancelButtonText: "Cancel",
                }).then(function (result) {
                    if (result.isConfirmed) {
                        window.location.href = "/logout";
                    }
                });
                return;
            }

            if (window.confirm("Are you sure you want to logout?")) {
                window.location.href = "/logout";
            }
        });
    }

    document.addEventListener("DOMContentLoaded", function () {
        var logoutAnchors = document.querySelectorAll('a[href="/logout"], a[href="logout"]');
        logoutAnchors.forEach(bindLogoutConfirm);
    });
})();

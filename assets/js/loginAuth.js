document.addEventListener("DOMContentLoaded", function () {
  const loginForm = document.getElementById("loginForm");
  const loginBtn = document.getElementById("loginBtn");
  const passwordInput = document.getElementById("loginPassword");
  const toggleIcon = document.getElementById("toggleIcon");

  // 1. Toggle Password Visibility Logic
  if (toggleIcon && passwordInput) {
    toggleIcon.addEventListener("click", () => {
      const type =
        passwordInput.getAttribute("type") === "password" ? "text" : "password";
      passwordInput.setAttribute("type", type);

      // Toggle the icon class
      if (type === "password") {
        toggleIcon.classList.remove("bi-eye-slash-fill");
        toggleIcon.classList.add("bi-eye-fill");
      } else {
        toggleIcon.classList.remove("bi-eye-fill");
        toggleIcon.classList.add("bi-eye-slash-fill");
      }
    });
  }

  // 2. Handle Login Submission
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const emailOrPhone = document.getElementById("emailOrPhone").value.trim();
      const password = passwordInput.value;

      // Simple validation
      if (!emailOrPhone || !password) {
        showNotification("Please fill in all fields.", "error");
        return;
      }

      // Show loading state on button
      setLoading(true);

      try {
        const response = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ emailOrPhone, password }),
        });

        const data = await response.json();

        if (data.success) {
          // Save user info
          localStorage.setItem("userId", data.userId);
          localStorage.setItem("fullname", data.fullname);
          localStorage.setItem("email", data.email); // Fixed: was missing in some versions
          localStorage.setItem("phone", data.phone);
          localStorage.setItem("loginTime", new Date().getTime());

          showNotification("Login successful! Redirecting...", "success");

          // Delay slightly to show the success message before redirecting
          setTimeout(() => {
            window.location.href = "/dashboard";
          }, 1000);
        } else {
          // Show error notification (Wrong password/email)
          showNotification(
            data.message || "Invalid email or password",
            "error"
          );
          setLoading(false);
        }
      } catch (error) {
        console.error("Login error:", error);
        showNotification(
          "Server connection failed. Please try again.",
          "error"
        );
        setLoading(false);
      }
    });
  }

  // Helper: Show Notification Pop-up (The Toast)
  function showNotification(message, type) {
    // Remove existing toast if any (prevents stacking too many)
    const existingToast = document.querySelector(".notification-toast");
    if (existingToast) existingToast.remove();

    // Create element
    const toast = document.createElement("div");
    toast.className = `notification-toast toast-${type}`;

    // Icon based on type
    const iconClass =
      type === "success"
        ? "bi-check-circle-fill"
        : "bi-exclamation-triangle-fill";

    toast.innerHTML = `
        <i class="bi ${iconClass} toast-icon"></i>
        <span style="font-weight: 500; color: #333;">${message}</span>
    `;

    document.body.appendChild(toast);

    // Auto remove after 3 seconds
    setTimeout(() => {
      // Add slide out animation
      toast.style.animation = "slideOutRight 0.3s ease-in forwards";
      // Wait for animation to finish then remove from DOM
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 300);
    }, 3000);
  }

  // Helper: Toggle Loading Button State
  function setLoading(isLoading) {
    if (!loginBtn) return;

    if (isLoading) {
      loginBtn.disabled = true;
      loginBtn.innerHTML =
        '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Logging in...';
    } else {
      loginBtn.disabled = false;
      loginBtn.innerHTML = "LOGIN";
    }
  }
});

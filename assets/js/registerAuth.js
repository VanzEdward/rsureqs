// -------------------------
// Register Auth with live validation - UPDATED FOR SPLIT NAMES
// -------------------------
const registerForm = document.getElementById("registerForm");
const alertBox = document.getElementById("registerAlert");

// --- NEW INPUTS ---
const lastNameInput = document.getElementById("lastName");
const firstNameInput = document.getElementById("firstName");
const middleNameInput = document.getElementById("middleName"); // Optional
const genderInput = document.getElementById("gender");
// --- END NEW INPUTS ---

// Existing Inputs
const emailInput = document.getElementById("email");
const phoneInput = document.getElementById("phone");
const passwordInput = document.getElementById("registerPassword");
const confirmPasswordInput = document.getElementById("confirmPassword");
const confirmMsg = document.getElementById("confirmMsg");
// const privacyCheckbox = document.getElementById("privacy"); // <-- REMOVED

// Add checklist elements for live validation
const passwordChecklist = {
  length: document.getElementById("length"),
  uppercase: document.getElementById("uppercase"),
  lowercase: document.getElementById("lowercase"),
  number: document.getElementById("number"),
  special: document.getElementById("special"),
};

// ===================================
// LIVE VALIDATION
// ===================================

// Live validation for password (no change needed here as IDs remain the same)
if (passwordInput && passwordChecklist.length) {
  passwordInput.addEventListener("input", () => {
    const val = passwordInput.value;
    passwordChecklist.length.classList.toggle("valid", val.length >= 8);
    passwordChecklist.uppercase.classList.toggle("valid", /[A-Z]/.test(val));
    passwordChecklist.lowercase.classList.toggle("valid", /[a-z]/.test(val));
    passwordChecklist.number.classList.toggle("valid", /\d/.test(val));
    passwordChecklist.special.classList.toggle("valid", /[!@#$%^&*]/.test(val));
  });
}

// Confirm password live check
if (confirmPasswordInput && passwordInput && confirmMsg) {
  confirmPasswordInput.addEventListener("input", () => {
    confirmMsg.classList.toggle(
      "d-none",
      confirmPasswordInput.value === passwordInput.value
    );
  });
}

// Live validation for email (no change needed)
if (emailInput) {
  emailInput.addEventListener("input", () => {
    const regex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
    emailInput.classList.toggle("is-valid", regex.test(emailInput.value));
    emailInput.classList.toggle("is-invalid", !regex.test(emailInput.value));
  });
}

// Live validation for phone number (no change needed)
if (phoneInput) {
  phoneInput.addEventListener("input", () => {
    const regex = /^09\d{9}$/;
    phoneInput.classList.toggle("is-valid", regex.test(phoneInput.value));
    phoneInput.classList.toggle("is-invalid", !regex.test(phoneInput.value));
  });
}

// **REMOVED OLD fullNameInput validation which caused the "Cannot read properties of null" error**

// ===================================
// FORM SUBMIT
// ===================================
if (registerForm) {
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    // --- Collect NEW split fields ---
    const lastName = lastNameInput ? lastNameInput.value.trim() : "";
    const firstName = firstNameInput ? firstNameInput.value.trim() : "";
    const middleName = middleNameInput ? middleNameInput.value.trim() : "";
    const gender = genderInput ? genderInput.value : "";
    // --- End NEW split fields ---

    // Collect existing fields
    const email = emailInput.value.trim();
    const phone = phoneInput.value.trim();
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    // const privacy = privacyCheckbox.checked; // <-- REMOVED

    // Validation regex
    const nameRegex = /^[A-Za-z\s]{2,50}$/;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
    const phoneRegex = /^09\d{9}$/;

    // --- NEW: Check split name fields ---
    if (!nameRegex.test(lastName)) {
      alertBox.className = "alert alert-danger";
      alertBox.textContent = "Last Name must be 2-50 letters and spaces only.";
      alertBox.classList.remove("d-none");
      return;
    }
    if (!nameRegex.test(firstName)) {
      alertBox.className = "alert alert-danger";
      alertBox.textContent = "First Name must be 2-50 letters and spaces only.";
      alertBox.classList.remove("d-none");
      return;
    }
    if (!nameRegex.test(middleName)) {
      alertBox.className = "alert alert-danger";
      alertBox.textContent =
        "Last, First, and Middle Name must be letters only.";
      alertBox.classList.remove("d-none");
      return;
    }
    if (!gender) {
      alertBox.className = "alert alert-danger";
      alertBox.textContent = "Please select your Gender.";
      alertBox.classList.remove("d-none");
      return;
    }
    // --- End NEW: Check split name fields ---

    // Check email
    if (!emailRegex.test(email)) {
      alertBox.className = "alert alert-danger";
      alertBox.textContent = "Email must be a valid Gmail address.";
      alertBox.classList.remove("d-none");
      return;
    }

    // Check phone
    if (!phoneRegex.test(phone)) {
      alertBox.className = "alert alert-danger";
      alertBox.textContent =
        "Phone number must start with 09 and be 11 digits.";
      alertBox.classList.remove("d-none");
      return;
    }

    /*
    // Check privacy policy <-- REMOVED
    if (!privacy) {
      alertBox.className = "alert alert-danger";
      alertBox.textContent = "You must agree to the Data Privacy Policy.";
      alertBox.classList.remove("d-none");
      return;
    }
    */

    // Check password strength
    const checklist = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /\d/.test(password),
      special: /[!@#$%^&*]/.test(password),
    };

    if (Object.values(checklist).includes(false)) {
      alertBox.className = "alert alert-danger";
      alertBox.textContent = "Password does not meet requirements.";
      alertBox.classList.remove("d-none");
      return;
    }

    if (password !== confirmPassword) {
      alertBox.className = "alert alert-danger";
      alertBox.textContent = "Passwords do not match.";
      alertBox.classList.remove("d-none");
      return;
    }

    // Send registration request
    try {
      const response = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // --- UPDATED BODY FOR SPLIT NAMES ---
        body: JSON.stringify({
          lastName,
          firstName,
          middleName,
          gender,
          email,
          phone,
          password,
        }),
        // --- END UPDATED BODY ---
      });

      const data = await response.json();

      if (data.success) {
        alertBox.className = "alert alert-success";
        alertBox.textContent =
          "Registration successful! Redirecting to login...";
        alertBox.classList.remove("d-none");

        setTimeout(() => {
          window.location.href = "/login";
        }, 1500);
      } else {
        alertBox.className = "alert alert-danger";
        alertBox.textContent = data.message;
        alertBox.classList.remove("d-none");
      }
    } catch (error) {
      console.error("❌ Register error:", error);
      alertBox.className = "alert alert-danger";
      alertBox.textContent = "Something went wrong. Please try again.";
      alertBox.classList.remove("d-none");
    }
  });
}
document.addEventListener("DOMContentLoaded", function () {
  // Get elements for the first password field
  const password = document.getElementById("registerPassword");
  const toggleIcon = document.getElementById("toggleIcon"); // This is the <i> tag

  // Get elements for the confirm password field
  const confirmPassword = document.getElementById("confirmPassword");
  const toggleIconConfirm = document.getElementById("toggleIconConfirm"); // This is the <i> tag

  // Reusable function to toggle a field
  function toggleFieldType(field, icon) {
    // Toggle the type
    const type =
      field.getAttribute("type") === "password" ? "text" : "password";
    field.setAttribute("type", type);

    // Toggle the icon
    if (type === "password") {
      icon.classList.remove("bi-eye-slash-fill");
      icon.classList.add("bi-eye-fill");
    } else {
      icon.classList.remove("bi-eye-fill");
      icon.classList.add("bi-eye-slash-fill");
    }
  }

  // Add click listener *directly to the icon*
  if (toggleIcon) {
    toggleIcon.addEventListener("click", function () {
      toggleFieldType(password, toggleIcon);
    });
  }

  // Add click listener *directly to the icon*
  if (toggleIconConfirm) {
    toggleIconConfirm.addEventListener("click", function () {
      toggleFieldType(confirmPassword, toggleIconConfirm);
    });
  }
});

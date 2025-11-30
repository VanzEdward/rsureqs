// Initialize managers
let serviceRequestManager;
let queueManager;
let isQueuePaused = false;

// Admin Dashboard Authentication Helper
const adminToken = localStorage.getItem("adminToken");
console.log(
  "Admin token from localStorage:",
  adminToken ? "Present" : "Missing"
);

// Function to make authenticated API calls
function makeAuthenticatedRequest(url, options = {}) {
  if (!adminToken) {
    console.error("No admin token found, redirecting to login");
    adminLogout();
    return Promise.reject("No admin token");
  }

  const defaultOptions = {
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
      ...options.headers,
    },
  };

  console.log("Making authenticated request to:", url);
  return fetch(url, { ...defaultOptions, ...options });
}

// Check authentication on page load
if (!adminToken) {
  window.location.href = "/adminLogin";
} else {
  console.log("Admin token found, verifying...");
  // Verify token is still valid on page load
  makeAuthenticatedRequest("/api/admin/me")
    .then((response) => {
      console.log("Auth check response status:", response.status);
      return response.json();
    })
    .then((data) => {
      console.log("Auth check response:", data);
      if (!data.success) {
        console.log("Token invalid, logging out");
        adminLogout();
      } else {
        console.log("Admin logged in:", data.admin.full_name);
        // You can display admin info in the dashboard
        if (document.getElementById("adminName")) {
          document.getElementById("adminName").textContent =
            data.admin.full_name;
        }

        // Load initial data after successful auth
        if (queueManager) {
          queueManager.loadQueues();
        }
        if (serviceRequestManager) {
          serviceRequestManager.loadServiceRequests();
        }
      }
    })
    .catch((error) => {
      console.error("Auth check failed:", error);
      adminLogout();
    });
}

// Admin logout function
function adminLogout() {
  localStorage.removeItem("admin");
  localStorage.removeItem("adminToken");
  window.location.href = "/adminLogin";
}

// Navigation functionality
document.addEventListener("DOMContentLoaded", function () {
  console.log("Admin dashboard initialized");

  // Initialize managers
  serviceRequestManager = new ServiceRequestManager();
  queueManager = new QueueManager();

  // Set up navigation
  setupNavigation();

  // Show initial page
  showPage("queue");

  // Load preferences
  loadPreferences();

  // Set up auto-refresh
  setupAutoRefresh();
});

function setupNavigation() {
  const menuItems = document.querySelectorAll(".menu-item");

  menuItems.forEach((item) => {
    item.addEventListener("click", () => {
      const targetPage = item.getAttribute("data-page");

      // Remove active class from all menu items and pages
      menuItems.forEach((mi) => mi.classList.remove("active"));
      document
        .querySelectorAll(".page")
        .forEach((page) => page.classList.remove("active"));

      // Add active class to clicked item
      item.classList.add("active");

      // Show target page
      showPage(targetPage);
    });
  });
}

function showPage(page) {
  // Hide all pages
  document
    .querySelectorAll(".page")
    .forEach((p) => p.classList.remove("active"));

  // Show target page
  const pageToShow = document.getElementById(page + "-page");
  if (pageToShow) {
    pageToShow.classList.add("active");

    // Refresh data for specific pages
    if (page === "queue" && queueManager) {
      queueManager.loadQueues();
    } else if (page === "documents" && serviceRequestManager) {
      serviceRequestManager.loadServiceRequests();
    } else if (page === "reports") {
      updateReportsData();
    }
  } else {
    console.error("Page not found:", page);
    // Fallback to queue page
    document.getElementById("queue-page").classList.add("active");
  }
}

function showReportDetail() {
  showPage("report-detail");
}

function toggleQueuePause() {
  isQueuePaused = !isQueuePaused;
  const btn = document.getElementById("pauseQueueBtn");
  if (isQueuePaused) {
    btn.innerHTML = "▶️ Resume Queue";
    showNotification("Queue processing paused", "warning");
  } else {
    btn.innerHTML = "⏸️ Pause Queue";
    showNotification("Queue processing resumed", "success");
  }
}

function updateReportsData() {
  // Update report statistics
  if (queueManager && queueManager.queues) {
    const total =
      (queueManager.queues.waiting || []).length +
      (queueManager.queues.processing || []).length +
      (queueManager.queues.completed || []).length;

    document.getElementById("totalRequestsSummary").textContent = total;
    document.getElementById("completedSummary").textContent = (
      queueManager.queues.completed || []
    ).length;
    document.getElementById("totalRequestsToday").textContent = total;
  }
}

function setupAutoRefresh() {
  // Refresh queue data every 10 seconds
  setInterval(() => {
    if (
      !isQueuePaused &&
      document.getElementById("queue-page").classList.contains("active")
    ) {
      queueManager.loadQueues();
    }
  }, 10000);

  // Refresh service requests every 30 seconds
  setInterval(() => {
    if (
      document.getElementById("documents-page").classList.contains("active")
    ) {
      serviceRequestManager.loadServiceRequests();
    }
  }, 30000);
}

// Modal functions
function toggleModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.toggle("active");
  }
}

// Close modal when clicking outside
window.onclick = function (event) {
  if (event.target.classList.contains("modal")) {
    event.target.classList.remove("active");
  }
};

// Theme toggle
let currentTheme = "light";
function toggleTheme() {
  currentTheme = currentTheme === "light" ? "dark" : "light";
  document.getElementById("themeValue").textContent =
    currentTheme === "light" ? "Light" : "Dark";

  if (currentTheme === "dark") {
    document.documentElement.setAttribute("data-theme", "dark");
    document.body.classList.add("dark-theme");
  } else {
    document.documentElement.removeAttribute("data-theme");
    document.body.classList.remove("dark-theme");
  }

  showNotification(
    "Theme changed to " + (currentTheme === "light" ? "Light" : "Dark")
  );

  // Save to localStorage
  localStorage.setItem("adminTheme", currentTheme);
}

// Font size toggle
const fontSizes = ["Small", "Medium", "Large"];
let currentFontSizeIndex = 1;
function toggleFontSize() {
  currentFontSizeIndex = (currentFontSizeIndex + 1) % fontSizes.length;
  const fontSize = fontSizes[currentFontSizeIndex];
  document.getElementById("fontSizeValue").textContent = fontSize;

  const sizes = {
    Small: "14px",
    Medium: "16px",
    Large: "18px",
  };

  document.body.style.fontSize = sizes[fontSize];
  showNotification("Font size changed to " + fontSize);

  // Save to localStorage
  localStorage.setItem("adminFontSize", fontSize);
}

// Load saved preferences
function loadPreferences() {
  // Load theme
  const savedTheme = localStorage.getItem("adminTheme");
  if (savedTheme) {
    currentTheme = savedTheme;
    document.getElementById("themeValue").textContent =
      savedTheme === "light" ? "Light" : "Dark";
    if (savedTheme === "dark") {
      document.documentElement.setAttribute("data-theme", "dark");
      document.body.classList.add("dark-theme");
    }
  }

  // Load font size
  const savedFontSize = localStorage.getItem("adminFontSize");
  if (savedFontSize) {
    const sizes = { Small: "14px", Medium: "16px", Large: "18px" };
    document.body.style.fontSize = sizes[savedFontSize];
    document.getElementById("fontSizeValue").textContent = savedFontSize;
    currentFontSizeIndex = fontSizes.indexOf(savedFontSize);
  }
}

// Save functions
function saveAccountDetails() {
  showNotification("Account details saved successfully!");
  toggleModal("accountDetailsModal");
}

function changePassword() {
  showNotification("Password changed successfully!");
  toggleModal("passwordModal");
}

function saveWaitingTime() {
  showNotification("Waiting time settings saved!");
  toggleModal("waitingTimeModal");
}

function saveMonitoring() {
  showNotification("Monitoring settings saved!");
  toggleModal("monitoringModal");
}

function saveNotification() {
  showNotification("Notification settings saved!");
  toggleModal("notificationModal");
}

function handleLogout() {
  if (confirm("Are you sure you want to log out?")) {
    showNotification("Logging out...");
    setTimeout(() => {
      adminLogout();
    }, 1000);
  }
}

// Notification system
function showNotification(message, type = "success") {
  // Remove existing notification if any
  const existingNotif = document.querySelector(".notification-toast");
  if (existingNotif) {
    existingNotif.remove();
  }

  // Create notification
  const notification = document.createElement("div");
  notification.className = "notification-toast";
  notification.textContent = message;

  // Style based on type
  const bgColor =
    type === "error" ? "#d32f2f" : type === "warning" ? "#f57c00" : "#2e7d32";
  notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${bgColor};
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            z-index: 10000;
            animation: slideInRight 0.3s ease-out;
        `;

  document.body.appendChild(notification);

  // Remove after 3 seconds
  setTimeout(() => {
    if (notification.parentNode) {
      notification.style.animation = "slideOutRight 0.3s ease-out";
      setTimeout(() => {
        if (notification.parentNode) {
          notification.remove();
        }
      }, 300);
    }
  }, 3000);
}

// Service Request Management
class ServiceRequestManager {
  constructor() {
    this.currentAdmin = "Jila Santos";
    this.requests = [];
  }

  async loadServiceRequests() {
    try {
      console.log("Loading service requests...");
      const response = await makeAuthenticatedRequest(
        "/api/admin/service-requests"
      );

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();

      if (result.success) {
        this.requests = result.requests || [];
        this.renderRequests();
        this.updateStats();
        console.log(
          "Service requests loaded successfully:",
          this.requests.length
        );
      } else {
        console.error("Error loading service requests:", result.message);
        this.showEmptyState();
        showNotification(
          "Failed to load service requests: " + result.message,
          "error"
        );
      }
    } catch (error) {
      console.error("Error loading service requests:", error);
      this.showEmptyState();
      if (error.message.includes("No admin token")) {
        showNotification("Session expired. Please login again.", "error");
        adminLogout();
      } else {
        showNotification("Failed to load service requests", "error");
      }
    }
  }

  showEmptyState() {
    const containers = [
      "pendingRequestsContainer",
      "approvedRequestsContainer",
      "declinedRequestsContainer",
    ];

    containers.forEach((containerId) => {
      const container = document.getElementById(containerId);
      if (container) {
        container.innerHTML = `
                        <div class="empty-state">
                            <div style="text-align: center; padding: 40px; color: #999;">
                                <div style="font-size: 3rem;">📋</div>
                                <p style="margin-top: 10px;">No service requests found.</p>
                            </div>
                        </div>
                    `;
      }
    });

    this.updateStats();
  }

  renderRequests() {
    this.renderPendingRequests();
    this.renderApprovedRequests();
    this.renderDeclinedRequests();
  }

  renderPendingRequests() {
    const container = document.getElementById("pendingRequestsContainer");
    if (!container) return;

    const pendingRequests = this.requests.filter(
      (req) => req.status === "pending"
    );

    if (pendingRequests.length === 0) {
      container.innerHTML = `
                    <div class="empty-state">
                        <div style="text-align: center; padding: 40px; color: #999;">
                            <div style="font-size: 3rem;">⏳</div>
                            <p style="margin-top: 10px;">No pending service requests.</p>
                        </div>
                    </div>
                `;
      return;
    }

    container.innerHTML = pendingRequests
      .map(
        (request) => `
                        <div class="document-item">
                            <div class="document-header">
                                <div>
                                    <div class="document-title">${this.escapeHtml(
                                      request.services.join(", ")
                                    )}</div>
                                    <div class="document-description">
                                        Requested by: ${this.escapeHtml(
                                          request.user_name
                                        )} (${this.escapeHtml(
          request.student_id
        )})<br>
                                        Course: ${this.escapeHtml(
                                          request.course
                                        )} - ${this.escapeHtml(
          request.year_level
        )}<br>
                                        Total Amount: ₱${parseFloat(
                                          request.total_amount || 0
                                        ).toFixed(2)}
                                    </div>
                                </div>
                                <div class="queue-number">Request ID: ${this.escapeHtml(
                                  request.request_id
                                )}</div>
                            </div>
                            <div class="document-meta">
                                <span>Submitted: ${new Date(
                                  request.submitted_at
                                ).toLocaleString()}</span>
                                <div class="button-group" style="margin-top: 10px;">
                                    <button class="btn btn-success btn-sm" onclick="serviceRequestManager.showApproveModal('${
                                      request.request_id
                                    }')">
                                        ✓ Approve
                                    </button>
                                    <button class="btn btn-danger btn-sm" onclick="serviceRequestManager.showDeclineModal('${
                                      request.request_id
                                    }')">
                                        ✗ Decline
                                    </button>
                                    <button class="btn btn-primary btn-sm" onclick="serviceRequestManager.viewRequestDetails('${
                                      request.request_id
                                    }')">
                                        👁️ View Details
                                    </button>
                                </div>
                            </div>
                        </div>
                    `
      )
      .join("");
  }

  renderApprovedRequests() {
    const container = document.getElementById("approvedRequestsContainer");
    if (!container) return;

    const approvedRequests = this.requests.filter(
      (req) => req.status === "approved"
    );

    if (approvedRequests.length === 0) {
      container.innerHTML = `
                    <div class="empty-state">
                        <div style="text-align: center; padding: 40px; color: #999;">
                            <div style="font-size: 3rem;">✅</div>
                            <p style="margin-top: 10px;">No approved service requests.</p>
                        </div>
                    </div>
                `;
      return;
    }

    container.innerHTML = approvedRequests
      .map(
        (request) => `
                        <div class="document-item approved">
                            <div class="document-header">
                                <div>
                                    <div class="document-title">${this.escapeHtml(
                                      request.services.join(", ")
                                    )}</div>
                                    <div class="document-description">
                                        Requested by: ${this.escapeHtml(
                                          request.user_name
                                        )} (${this.escapeHtml(
          request.student_id
        )})<br>
                                        ${
                                          request.approved_by
                                            ? `Approved by: ${this.escapeHtml(
                                                request.approved_by
                                              )}<br>`
                                            : ""
                                        }
                                        ${
                                          request.approved_at
                                            ? `Approved at: ${new Date(
                                                request.approved_at
                                              ).toLocaleString()}`
                                            : ""
                                        }
                                    </div>
                                </div>
                                <div class="queue-number">
                                    <span class="badge approved-badge">Approved</span>
                                </div>
                            </div>
                            <div class="document-meta">
                                <span>Request ID: ${this.escapeHtml(
                                  request.request_id
                                )}</span>
                            </div>
                        </div>
                    `
      )
      .join("");
  }

  renderDeclinedRequests() {
    const container = document.getElementById("declinedRequestsContainer");
    if (!container) return;

    const declinedRequests = this.requests.filter(
      (req) => req.status === "declined"
    );

    if (declinedRequests.length === 0) {
      container.innerHTML = `
                    <div class="empty-state">
                        <div style="text-align: center; padding: 40px; color: #999;">
                            <div style="font-size: 3rem;">❌</div>
                            <p style="margin-top: 10px;">No declined service requests.</p>
                        </div>
                    </div>
                `;
      return;
    }

    container.innerHTML = declinedRequests
      .map(
        (request) => `
                        <div class="document-item declined">
                            <div class="document-header">
                                <div>
                                    <div class="document-title">${this.escapeHtml(
                                      request.services.join(", ")
                                    )}</div>
                                    <div class="document-description">
                                        Requested by: ${this.escapeHtml(
                                          request.user_name
                                        )} (${this.escapeHtml(
          request.student_id
        )})<br>
                                        ${
                                          request.declined_by
                                            ? `Declined by: ${this.escapeHtml(
                                                request.declined_by
                                              )}<br>`
                                            : ""
                                        }
                                        ${
                                          request.decline_reason
                                            ? `Reason: ${this.escapeHtml(
                                                request.decline_reason
                                              )}`
                                            : ""
                                        }
                                    </div>
                                </div>
                                <div class="queue-number">
                                    <span class="badge declined-badge">Declined</span>
                                </div>
                            </div>
                            <div class="document-meta">
                                <span>${
                                  request.declined_at
                                    ? `Declined at: ${new Date(
                                        request.declined_at
                                      ).toLocaleString()}`
                                    : "Declined"
                                }</span>
                            </div>
                        </div>
                    `
      )
      .join("");
  }

  updateStats() {
    const pendingCount = this.requests.filter(
      (req) => req.status === "pending"
    ).length;
    const approvedCount = this.requests.filter(
      (req) => req.status === "approved"
    ).length;
    const declinedCount = this.requests.filter(
      (req) => req.status === "declined"
    ).length;

    const pendingElement = document.getElementById("pendingCount");
    const approvedElement = document.getElementById("approvedCount");
    const declinedElement = document.getElementById("declinedCount");

    if (pendingElement) pendingElement.textContent = pendingCount;
    if (approvedElement) approvedElement.textContent = approvedCount;
    if (declinedElement) declinedElement.textContent = declinedCount;
  }

  showApproveModal(requestId) {
    const request = this.requests.find((req) => req.request_id === requestId);
    if (!request) return;

    document.getElementById("approveRequestId").value = requestId;
    document.getElementById("approveRequestDetails").innerHTML =
      this.getRequestDetailsHTML(request);
    document.getElementById("approveNotes").value = "";

    toggleModal("approveRequestModal");
  }

  showDeclineModal(requestId) {
    const request = this.requests.find((req) => req.request_id === requestId);
    if (!request) return;

    document.getElementById("declineRequestId").value = requestId;
    document.getElementById("declineRequestDetails").innerHTML =
      this.getRequestDetailsHTML(request);
    document.getElementById("declineReason").value = "";

    toggleModal("declineRequestModal");
  }

  viewRequestDetails(requestId) {
    const request = this.requests.find((req) => req.request_id === requestId);
    if (!request) return;

    document.getElementById("requestDetailsContent").innerHTML =
      this.getDetailedRequestHTML(request);
    toggleModal("requestDetailsModal");
  }

  getRequestDetailsHTML(request) {
    return `
                <div class="request-preview">
                    <strong>Student:</strong> ${this.escapeHtml(
                      request.user_name
                    )} (${this.escapeHtml(request.student_id)})<br>
                    <strong>Course:</strong> ${this.escapeHtml(
                      request.course
                    )} - ${this.escapeHtml(request.year_level)}<br>
                    <strong>Services:</strong> ${this.escapeHtml(
                      request.services.join(", ")
                    )}<br>
                    <strong>Total Amount:</strong> ₱${parseFloat(
                      request.total_amount || 0
                    ).toFixed(2)}<br>
                    <strong>Submitted:</strong> ${new Date(
                      request.submitted_at
                    ).toLocaleString()}
                </div>
            `;
  }

  getDetailedRequestHTML(request) {
    const services = Array.isArray(request.services) ? request.services : [];
    const requirements = Array.isArray(request.requirements)
      ? request.requirements
      : [];

    const requirementsHTML = requirements
      .map(
        (req) => `
                        <div class="requirement-item">
                            <strong>${this.escapeHtml(
                              req.service || "Service"
                            )}:</strong><br>
                            <ul>
                                ${(req.requirements || [])
                                  .map((r) => `<li>${this.escapeHtml(r)}</li>`)
                                  .join("")}
                            </ul>
                        </div>
                    `
      )
      .join("");

    return `
                <div class="request-details">
                    <div class="info-row">
                        <span class="info-label">Request ID:</span>
                        <span class="info-value">${this.escapeHtml(
                          request.request_id
                        )}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Student Name:</span>
                        <span class="info-value">${this.escapeHtml(
                          request.user_name
                        )}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Student ID:</span>
                        <span class="info-value">${this.escapeHtml(
                          request.student_id
                        )}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Course & Year:</span>
                        <span class="info-value">${this.escapeHtml(
                          request.course
                        )} - ${this.escapeHtml(request.year_level)}</span>
                    </div>
                    ${
                      request.contact_email
                        ? `
                        <div class="info-row">
                            <span class="info-label">Contact Email:</span>
                            <span class="info-value">${this.escapeHtml(
                              request.contact_email
                            )}</span>
                        </div>
                    `
                        : ""
                    }
                    ${
                      request.contact_phone
                        ? `
                        <div class="info-row">
                            <span class="info-label">Contact Phone:</span>
                            <span class="info-value">${this.escapeHtml(
                              request.contact_phone
                            )}</span>
                        </div>
                    `
                        : ""
                    }
                    <div class="info-row">
                        <span class="info-label">Submitted:</span>
                        <span class="info-value">${new Date(
                          request.submitted_at
                        ).toLocaleString()}</span>
                    </div>
                    
                    <h4>Requested Services</h4>
                    <div class="services-list">
                        ${services
                          .map(
                            (service) => `
                                    <div class="service-item">
                                        <strong>• ${this.escapeHtml(
                                          service
                                        )}</strong>
                                    </div>
                                `
                          )
                          .join("")}
                        <div class="total-amount">
                            <strong>Total Amount: ₱${parseFloat(
                              request.total_amount || 0
                            ).toFixed(2)}</strong>
                        </div>
                    </div>

                    ${
                      requirements.length > 0
                        ? `
                        <h4>Requirements</h4>
                        <div class="requirements-list">
                            ${requirementsHTML}
                        </div>
                    `
                        : ""
                    }

                    ${
                      request.status === "approved" && request.approved_by
                        ? `
                        <div class="approval-details">
                            <strong>Approval Details:</strong><br>
                            Approved by: ${this.escapeHtml(
                              request.approved_by
                            )}<br>
                            ${
                              request.approved_at
                                ? `Approved at: ${new Date(
                                    request.approved_at
                                  ).toLocaleString()}<br>`
                                : ""
                            }
                            ${
                              request.approve_notes
                                ? `Notes: ${this.escapeHtml(
                                    request.approve_notes
                                  )}`
                                : ""
                            }
                        </div>
                    `
                        : ""
                    }

                    ${
                      request.status === "declined" && request.declined_by
                        ? `
                        <div class="decline-details">
                            <strong>Decline Details:</strong><br>
                            Declined by: ${this.escapeHtml(
                              request.declined_by
                            )}<br>
                            ${
                              request.declined_at
                                ? `Declined at: ${new Date(
                                    request.declined_at
                                  ).toLocaleString()}<br>`
                                : ""
                            }
                            ${
                              request.decline_reason
                                ? `Reason: ${this.escapeHtml(
                                    request.decline_reason
                                  )}`
                                : ""
                            }
                        </div>
                    `
                        : ""
                    }
                </div>
            `;
  }

  async confirmApproveRequest() {
    const requestId = document.getElementById("approveRequestId").value;
    const notes = document.getElementById("approveNotes").value;

    try {
      const response = await makeAuthenticatedRequest(
        "/api/admin/approve-request",
        {
          method: "POST",
          body: JSON.stringify({
            requestId: requestId,
            approveNotes: notes,
          }),
        }
      );

      const result = await response.json();

      if (result.success) {
        toggleModal("approveRequestModal");
        showNotification("Request approved successfully!");

        // Reload data
        await this.loadServiceRequests();

        // Refresh queue if on queue page
        if (
          queueManager &&
          document.getElementById("queue-page").classList.contains("active")
        ) {
          await queueManager.loadQueues();
        }
      } else {
        alert("Error approving request: " + result.message);
      }
    } catch (error) {
      console.error("Error approving request:", error);
      alert("Error approving request. Please try again.");
    }
  }

  async confirmDeclineRequest() {
    const requestId = document.getElementById("declineRequestId").value;
    const reason = document.getElementById("declineReason").value;

    if (!reason.trim()) {
      alert("Please provide a reason for declining.");
      return;
    }

    try {
      const response = await makeAuthenticatedRequest(
        "/api/admin/decline-request",
        {
          method: "POST",
          body: JSON.stringify({
            requestId: requestId,
            declineReason: reason,
          }),
        }
      );

      const result = await response.json();

      if (result.success) {
        toggleModal("declineRequestModal");
        await this.loadServiceRequests();
        showNotification("Request declined successfully!");
      } else {
        alert("Error declining request: " + result.message);
      }
    } catch (error) {
      console.error("Error declining request:", error);
      alert("Error declining request. Please try again.");
    }
  }

  // Utility function to prevent XSS
  escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return "";
    return String(unsafe)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
}

// Queue Manager
class QueueManager {
  constructor() {
    this.queues = {
      waiting: [],
      processing: [],
      ready: [],
      completed: [],
      priority: [],
    };
    this.isAutoRefresh = true;
    this.lastUpdate = null;
  }

  async loadQueues() {
    try {
      console.log("Loading queues...");
      const response = await makeAuthenticatedRequest("/api/admin/queues");

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();

      if (result.success) {
        this.queues = result.queues || {
          waiting: [],
          processing: [],
          ready: [],
          completed: [],
          priority: [],
        };
        this.renderQueueDashboard();
        this.updateQueueStats();
        updateReportsData();
        this.lastUpdate = new Date();
        console.log("Queues loaded successfully:", this.queues);
      } else {
        console.error("Error loading queues:", result.message);
        this.showEmptyQueueState();
        showNotification(
          "Failed to load queue data: " + result.message,
          "error"
        );
      }
    } catch (error) {
      console.error("Error loading queues:", error);
      this.showEmptyQueueState();
      if (error.message.includes("No admin token")) {
        showNotification("Session expired. Please login again.", "error");
        adminLogout();
      } else if (!error.message.includes("Failed to fetch")) {
        showNotification("Failed to load queue data", "error");
      }
    }
  }

  renderQueueDashboard() {
    this.renderCurrentRequest();
    this.renderPriorityQueue();
    this.renderRegularQueue();
    this.renderProcessingQueue();
  }

  renderCurrentRequest() {
    const currentProcessing = this.queues.processing[0];
    const currentRequestCard = document.getElementById("currentRequestCard");

    if (!currentRequestCard) return;

    if (!currentProcessing) {
      currentRequestCard.innerHTML = `
                    <div class="card-header">
                        <div>
                            <span class="card-title">Current Request</span>
                            <span class="badge inactive">No Active Request</span>
                        </div>
                    </div>
                    <div class="empty-state">
                        <div style="text-align: center; padding: 40px; color: #999;">
                            <div style="font-size: 3rem;">📋</div>
                            <p style="margin-top: 10px;">No request is currently being processed.</p>
                        </div>
                    </div>
                    <div class="button-group">
                        <button class="btn btn-primary" onclick="queueManager.processNextInQueue()" style="width: 100%;">
                            Process Next in Queue
                        </button>
                    </div>
                `;
      return;
    }

    const isPriority = currentProcessing.is_priority;
    const services = Array.isArray(currentProcessing.services)
      ? currentProcessing.services
      : [];

    const processingTime = this.getProcessingTime(currentProcessing.started_at);

    currentRequestCard.innerHTML = `
                <div class="card-header">
                    <div>
                        <span class="card-title">Current Request</span>
                        ${
                          isPriority
                            ? '<span class="badge priority">🔴 PRIORITY</span>'
                            : ""
                        }
                        <span class="badge processing">⏱️ Processing (${processingTime})</span>
                    </div>
                </div>
                <div class="info-row">
                    <span class="info-label">Queue Number:</span>
                    <span class="info-value">${this.escapeHtml(
                      currentProcessing.queue_number
                    )}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Full Name:</span>
                    <span class="info-value">${this.escapeHtml(
                      currentProcessing.user_name
                    )}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Student ID:</span>
                    <span class="info-value">${this.escapeHtml(
                      currentProcessing.student_id || "N/A"
                    )}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Services:</span>
                    <span class="info-value">${services.join(", ")}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Started:</span>
                    <span class="info-value">${new Date(
                      currentProcessing.started_at
                    ).toLocaleTimeString()}</span>
                </div>
                ${
                  isPriority
                    ? `
                    <div class="alert-box">
                        ℹ️ <strong>Priority Service:</strong> This request is prioritized.
                    </div>
                `
                    : ""
                }
                <div class="action-buttons">
                    <button class="btn btn-primary" onclick="queueManager.notifyStudent('${
                      currentProcessing.queue_id
                    }')">
                        🔔 Notify Student
                    </button>
                    <button class="btn btn-warning" onclick="queueManager.escalatePriority('${
                      currentProcessing.queue_id
                    }')">
                        ⚡ Escalate
                    </button>
                    <button class="btn btn-success" onclick="queueManager.markAsDone('${
                      currentProcessing.queue_id
                    }')">
                        ✓ Mark as Done
                    </button>
                    <button class="btn btn-secondary" onclick="queueManager.transferToStaff('${
                      currentProcessing.queue_id
                    }')">
                        👥 Transfer
                    </button>
                </div>
            `;
  }

  renderProcessingQueue() {
    const container = document.getElementById("processingQueueContainer");
    const badge = document.getElementById("processingBadge");

    if (!container) return;

    const processingQueues = this.queues.processing || [];

    if (badge) {
      badge.textContent = processingQueues.length;
    }

    if (processingQueues.length === 0) {
      container.innerHTML = `
                    <div class="empty-state">
                        <div style="text-align: center; padding: 20px; color: #999;">
                            No requests currently processing
                        </div>
                    </div>
                `;
      return;
    }

    container.innerHTML = processingQueues
      .map((queue, index) => {
        const services = Array.isArray(queue.services) ? queue.services : [];
        const processingTime = this.getProcessingTime(queue.started_at);
        const isCurrent = index === 0;

        return `
                    <div class="queue-item ${
                      isCurrent ? "queue-item-processing" : ""
                    }" style="padding: 15px; border-bottom: 1px solid #eee; ${
          !isCurrent ? "opacity: 0.7;" : ""
        }">
                        <div class="queue-header" style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                            <div>
                                <strong>${this.escapeHtml(
                                  queue.queue_number
                                )}</strong>
                                ${
                                  queue.is_priority
                                    ? '<span class="status-badge" style="background: #d32f2f; margin-left: 8px;">PRIORITY</span>'
                                    : ""
                                }
                                ${
                                  isCurrent
                                    ? '<span class="status-badge status-processing">CURRENT</span>'
                                    : '<span class="status-badge status-waiting">NEXT</span>'
                                }
                            </div>
                            <div style="text-align: right;">
                                <div style="font-size: 12px; color: #666;">${processingTime}</div>
                            </div>
                        </div>
                        <div style="font-size: 14px; margin-bottom: 5px;">${this.escapeHtml(
                          queue.user_name
                        )}</div>
                        <div style="font-size: 12px; color: #666; margin-bottom: 8px;">
                            ${services.slice(0, 2).join(", ")}${
          services.length > 2 ? ` +${services.length - 2} more` : ""
        }
                        </div>
                        <div class="action-buttons">
                            ${
                              !isCurrent
                                ? `
                                <button class="btn btn-sm btn-primary" onclick="queueManager.makeCurrent('${queue.queue_id}')">Make Current</button>
                            `
                                : ""
                            }
                            <button class="btn btn-sm btn-success" onclick="queueManager.markAsDone('${
                              queue.queue_id
                            }')">Complete</button>
                            <button class="btn btn-sm btn-warning" onclick="queueManager.notifyStudent('${
                              queue.queue_id
                            }')">Notify</button>
                        </div>
                    </div>
                `;
      })
      .join("");
  }

  renderPriorityQueue() {
    const priorityCard = document.getElementById("priorityQueueContainer");
    if (!priorityCard) return;

    const priorityQueues = this.queues.priority || [];

    priorityCard.innerHTML = `
                <div class="priority-header">
                    <div>
                        <div style="color: #c62828; font-size: 14px; font-weight: 600; margin-bottom: 5px;">
                            ❤️ Priority Queue (${priorityQueues.length})
                        </div>
                        <div style="font-size: 12px; color: #666">Next: ${
                          priorityQueues[0]
                            ? priorityQueues[0].queue_number
                            : "None"
                        }</div>
                    </div>
                    <button class="btn btn-sm btn-outline-danger" onclick="queueManager.clearPriorityQueue()" ${
                      priorityQueues.length === 0 ? "disabled" : ""
                    }>
                        Clear All
                    </button>
                </div>
                ${priorityQueues
                  .map((queue, index) => {
                    const services = Array.isArray(queue.services)
                      ? queue.services
                      : [];
                    return `
                        <div class="priority-queue-item" style="background: white; border-radius: 8px; padding: 15px; margin-top: 10px; border-left: 4px solid #c62828;">
                            <div class="queue-header" style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                                <div class="priority-id">${this.escapeHtml(
                                  queue.queue_number
                                )}</div>
                                <div>
                                    <span class="badge pwa">${this.escapeHtml(
                                      queue.priority_type || "Priority"
                                    )}</span>
                                    <span class="status-badge status-waiting">#${
                                      index + 1
                                    }</span>
                                </div>
                            </div>
                            <div style="font-size: 14px; color: #333; margin-bottom: 5px; font-weight: 600;">${this.escapeHtml(
                              queue.user_name
                            )}</div>
                            <div style="font-size: 12px; color: #666; margin-bottom: 3px;">
                                ${this.escapeHtml(
                                  queue.student_id || "N/A"
                                )} | ${this.escapeHtml(queue.course || "N/A")}
                            </div>
                            <div style="font-size: 12px; color: #999; margin-bottom: 8px;">
                                ${services.join(", ")}
                            </div>
                            <div style="font-size: 12px; color: #999;">
                                Submitted: ${new Date(
                                  queue.submitted_at
                                ).toLocaleTimeString()}
                            </div>
                            <div style="font-size: 14px; font-weight: 600; color: #c62828; margin-top: 10px;">
                                ₱${parseFloat(queue.total_amount || 0).toFixed(
                                  2
                                )}
                            </div>
                            <div class="action-buttons" style="margin-top: 10px;">
                                <button class="btn btn-sm btn-primary" onclick="queueManager.startProcessing('${
                                  queue.queue_id
                                }')">
                                    Start Processing
                                </button>
                                <button class="btn btn-sm btn-outline-secondary" onclick="queueManager.moveToRegular('${
                                  queue.queue_id
                                }')">
                                    Make Regular
                                </button>
                            </div>
                        </div>
                    `;
                  })
                  .join("")}
                ${
                  priorityQueues.length === 0
                    ? `
                    <div class="empty-state">
                        <div style="text-align: center; padding: 20px; color: #999;">
                            No priority requests
                        </div>
                    </div>
                `
                    : ""
                }
            `;
  }

  renderRegularQueue() {
    const regularQueueCard = document.getElementById("regularQueueContainer");
    if (!regularQueueCard) return;

    const regularQueues = this.queues.waiting || [];

    regularQueueCard.innerHTML = `
                <div class="card-header">
                    <span class="card-title">Regular Queue</span>
                    <span class="badge waiting">${
                      regularQueues.length
                    } waiting</span>
                </div>
                ${regularQueues
                  .slice(0, 8)
                  .map((queue, index) => {
                    const services = Array.isArray(queue.services)
                      ? queue.services
                      : [];
                    return `
                        <div class="queue-card" onclick="queueManager.startProcessing('${
                          queue.queue_id
                        }')" style="cursor: pointer; padding: 12px; border-bottom: 1px solid #f0f0f0;">
                            <div class="queue-header" style="display: flex; justify-content: space-between; align-items: start;">
                                <span class="queue-id">${this.escapeHtml(
                                  queue.queue_number
                                )}</span>
                                <span class="queue-status" style="text-align: right;">
                                    ${services[0] || "Service"}
                                    <br />
                                    <small style="color: #999">${new Date(
                                      queue.submitted_at
                                    ).toLocaleTimeString()}</small>
                                </span>
                            </div>
                            <div style="font-size: 14px; color: #666; margin-top: 5px;">
                                ${this.escapeHtml(queue.user_name)}
                            </div>
                            <div style="font-size: 12px; color: #999;">
                                ${this.escapeHtml(queue.student_id || "N/A")}
                            </div>
                            <div class="action-buttons" style="margin-top: 8px;">
                                <button class="btn btn-sm btn-outline-danger" onclick="event.stopPropagation(); queueManager.makePriority('${
                                  queue.queue_id
                                }')">
                                    Make Priority
                                </button>
                                <button class="btn btn-sm btn-outline-primary" onclick="event.stopPropagation(); queueManager.viewDetails('${
                                  queue.queue_id
                                }')">
                                    Details
                                </button>
                            </div>
                        </div>
                    `;
                  })
                  .join("")}
                ${
                  regularQueues.length === 0
                    ? `
                    <div class="empty-state">
                        <div style="text-align: center; padding: 20px; color: #999;">
                            No regular requests in queue
                        </div>
                    </div>
                `
                    : ""
                }
                ${
                  regularQueues.length > 8
                    ? `
                    <div style="padding: 15px; text-align: center; border-top: 1px solid #f0f0f0;">
                        <small class="text-muted">+${
                          regularQueues.length - 8
                        } more in queue</small>
                    </div>
                `
                    : ""
                }
                <div class="next-serve">
                    Next to serve: <strong>${this.getNextToServe()}</strong>
                </div>
            `;
  }

  getProcessingTime(startedAt) {
    if (!startedAt) return "0m";
    const start = new Date(startedAt);
    const now = new Date();
    const diff = Math.floor((now - start) / (1000 * 60)); // minutes
    return `${diff}m`;
  }

  getNextToServe() {
    if (this.queues.priority && this.queues.priority.length > 0) {
      const nextPriority = this.queues.priority[0];
      return `${nextPriority.queue_number} (Priority)`;
    }

    if (this.queues.waiting && this.queues.waiting.length > 0) {
      const nextRegular = this.queues.waiting[0];
      return `${nextRegular.queue_number} (Regular)`;
    }

    return "No pending requests";
  }

  updateQueueStats() {
    const waitingCount = (this.queues.waiting || []).length;
    const processingCount = (this.queues.processing || []).length;
    const completedCount = (this.queues.completed || []).length;
    const priorityCount = (this.queues.priority || []).length;

    document.getElementById("waitingCount").textContent = waitingCount;
    document.getElementById("processingCount").textContent = processingCount;
    document.getElementById("completedCount").textContent = completedCount;
    document.getElementById("priorityCount").textContent = priorityCount;
  }

  // New methods for enhanced functionality
  async makePriority(queueId) {
    if (!confirm("Make this request priority?")) return;

    try {
      const response = await makeAuthenticatedRequest(
        "/api/admin/make-priority",
        {
          method: "POST",
          body: JSON.stringify({ queueId }),
        }
      );

      const result = await response.json();
      if (result.success) {
        showNotification("Request moved to priority queue!");
        await this.loadQueues();
      } else {
        alert("Error: " + result.message);
      }
    } catch (error) {
      console.error("Error making priority:", error);
      alert("Error making priority. Please try again.");
    }
  }

  async makeCurrent(queueId) {
    try {
      const response = await makeAuthenticatedRequest(
        "/api/admin/make-current",
        {
          method: "POST",
          body: JSON.stringify({ queueId }),
        }
      );

      const result = await response.json();
      if (result.success) {
        showNotification("Request set as current!");
        await this.loadQueues();
      } else {
        alert("Error: " + result.message);
      }
    } catch (error) {
      console.error("Error making current:", error);
      alert("Error making current. Please try again.");
    }
  }

  async escalatePriority(queueId) {
    try {
      const response = await makeAuthenticatedRequest(
        "/api/admin/escalate-priority",
        {
          method: "POST",
          body: JSON.stringify({ queueId }),
        }
      );

      const result = await response.json();
      if (result.success) {
        showNotification("Priority escalated!");
        await this.loadQueues();
      }
    } catch (error) {
      console.error("Error escalating:", error);
    }
  }

  async transferToStaff(queueId) {
    const staff = prompt("Enter staff name to transfer to:");
    if (staff) {
      showNotification(`Transferred to ${staff}`);
      // Implementation would go here
    }
  }

  async clearPriorityQueue() {
    if (
      !confirm(
        "Clear all priority requests? This will move them to regular queue."
      )
    )
      return;

    try {
      const response = await makeAuthenticatedRequest(
        "/api/admin/clear-priority",
        {
          method: "POST",
        }
      );

      const result = await response.json();
      if (result.success) {
        showNotification("Priority queue cleared!");
        await this.loadQueues();
      }
    } catch (error) {
      console.error("Error clearing priority:", error);
    }
  }

  async moveToRegular(queueId) {
    try {
      const response = await makeAuthenticatedRequest(
        "/api/admin/move-to-regular",
        {
          method: "POST",
          body: JSON.stringify({ queueId }),
        }
      );

      const result = await response.json();
      if (result.success) {
        showNotification("Moved to regular queue");
        await this.loadQueues();
      }
    } catch (error) {
      console.error("Error moving to regular:", error);
    }
  }

  viewDetails(queueId) {
    // Implementation for viewing queue details
    alert("View details for: " + queueId);
  }

  async startProcessing(queueId) {
    if (!confirm("Start processing this request?")) return;

    try {
      const response = await makeAuthenticatedRequest(
        "/api/admin/start-processing",
        {
          method: "POST",
          body: JSON.stringify({ queueId }),
        }
      );

      const result = await response.json();
      if (result.success) {
        showNotification("Processing started!");
        await this.loadQueues();
      } else {
        alert("Error: " + result.message);
      }
    } catch (error) {
      console.error("Error starting processing:", error);
      alert("Error starting processing. Please try again.");
    }
  }

  async notifyStudent(queueId) {
    try {
      const response = await makeAuthenticatedRequest(
        "/api/admin/notify-student",
        {
          method: "POST",
          body: JSON.stringify({ queueId }),
        }
      );

      const result = await response.json();
      if (result.success) {
        showNotification("Student notified successfully!");
        // Update UI to show notified status
        this.updateNotificationStatus(queueId);
      } else {
        alert("Error: " + result.message);
      }
    } catch (error) {
      console.error("Error notifying student:", error);
      alert("Error notifying student. Please try again.");
    }
  }

  async markAsDone(queueId) {
    if (!confirm("Mark this request as completed?")) return;

    try {
      const response = await makeAuthenticatedRequest("/api/admin/mark-done", {
        method: "POST",
        body: JSON.stringify({ queueId }),
      });

      const result = await response.json();
      if (result.success) {
        showNotification(
          result.nextQueueStarted
            ? "Request completed! Next queue started automatically."
            : "Request completed!"
        );
        await this.loadQueues();
      } else {
        alert("Error: " + result.message);
      }
    } catch (error) {
      console.error("Error marking as done:", error);
      alert("Error completing request. Please try again.");
    }
  }

  async processNextInQueue() {
    const nextQueue =
      this.queues.priority && this.queues.priority.length > 0
        ? this.queues.priority[0]
        : this.queues.waiting && this.queues.waiting.length > 0
        ? this.queues.waiting[0]
        : null;

    if (!nextQueue) {
      alert("No requests in queue to process.");
      return;
    }

    await this.startProcessing(nextQueue.queue_id);
  }

  updateNotificationStatus(queueId) {
    // Update UI to show that student was notified
    const elements = document.querySelectorAll(`[onclick*="${queueId}"]`);
    elements.forEach((element) => {
      const btn = element
        .closest(".action-buttons")
        ?.querySelector('[onclick*="notifyStudent"]');
      if (btn) {
        btn.innerHTML = "✅ Notified";
        btn.disabled = true;
        btn.classList.remove("btn-primary");
        btn.classList.add("btn-success");
      }
    });
  }

  escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return "";
    return String(unsafe)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  showEmptyQueueState() {
    const stats = [
      "waitingCount",
      "processingCount",
      "completedCount",
      "priorityCount",
    ];
    stats.forEach((stat) => {
      const element = document.getElementById(stat);
      if (element) element.textContent = "0";
    });
  }
}

// Manual Queue Entry Function
async function addManualQueue() {
  const name = document.getElementById("manualName").value;
  const studentId = document.getElementById("manualStudentId").value;
  const service = document.getElementById("manualService").value;
  const isPriority = document.getElementById("manualPriority").value === "true";

  if (!name) {
    alert("Please enter a name");
    return;
  }

  // Show additional details modal
  document.getElementById("manualNameDisplay").textContent = name;
  document.getElementById("manualStudentIdDisplay").textContent =
    studentId || "N/A";
  document.getElementById("manualServiceDisplay").textContent = service;
  document.getElementById("manualPriorityDisplay").textContent = isPriority
    ? "Yes"
    : "No";

  toggleModal("manualTransactionModal");
}

async function confirmManualQueue() {
  const name = document.getElementById("manualName").value;
  const studentId = document.getElementById("manualStudentId").value;
  const service = document.getElementById("manualService").value;
  const isPriority = document.getElementById("manualPriority").value === "true";
  const transactionType = document.getElementById("transactionType").value;
  const notes = document.getElementById("transactionNotes").value;

  try {
    const response = await makeAuthenticatedRequest(
      "/api/admin/add-manual-queue",
      {
        method: "POST",
        body: JSON.stringify({
          name,
          studentId,
          service,
          isPriority,
          transactionType,
          notes,
        }),
      }
    );

    const result = await response.json();

    if (result.success) {
      showNotification(`Manual queue entry added: ${result.queueNumber}`);
      toggleModal("manualTransactionModal");

      // Clear form
      document.getElementById("manualName").value = "";
      document.getElementById("manualStudentId").value = "";
      document.getElementById("transactionNotes").value = "";

      // Refresh queues
      queueManager.loadQueues();
    } else {
      alert("Error: " + result.message);
    }
  } catch (error) {
    console.error("Error adding manual queue:", error);
    alert("Error adding to queue. Please try again.");
  }
}

// Enhanced auto-refresh with error handling
function setupEnhancedAutoRefresh() {
  // Refresh every 5 seconds when on queue page
  setInterval(() => {
    if (
      !isQueuePaused &&
      document.getElementById("queue-page").classList.contains("active")
    ) {
      queueManager.loadQueues();
    }
  }, 5000);

  // Refresh service requests every 30 seconds
  setInterval(() => {
    if (
      document.getElementById("documents-page").classList.contains("active")
    ) {
      serviceRequestManager.loadServiceRequests();
    }
  }, 30000);
}

// Initialize with enhanced features
document.addEventListener("DOMContentLoaded", function () {
  console.log("Admin dashboard initialized with enhanced features");

  // Initialize managers
  serviceRequestManager = new ServiceRequestManager();
  queueManager = new QueueManager();

  // Set up navigation
  setupNavigation();

  // Show initial page
  showPage("queue");

  // Load preferences
  loadPreferences();

  // Set up enhanced auto-refresh
  setupEnhancedAutoRefresh();
});

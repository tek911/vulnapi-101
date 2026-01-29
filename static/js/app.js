/**
 * VulnAPI-101 Frontend JavaScript
 * Provides functionality to interact with the vulnerable API
 */

const API_BASE = '/api';
let authToken = localStorage.getItem('vulnapi_token') || '';
let currentUser = JSON.parse(localStorage.getItem('vulnapi_user') || 'null');

// ==================== Utility Functions ====================

function setToken(token) {
    authToken = token;
    localStorage.setItem('vulnapi_token', token);
}

function setCurrentUser(user) {
    currentUser = user;
    localStorage.setItem('vulnapi_user', JSON.stringify(user));
    updateAuthUI();
}

function clearAuth() {
    authToken = '';
    currentUser = null;
    localStorage.removeItem('vulnapi_token');
    localStorage.removeItem('vulnapi_user');
    updateAuthUI();
}

function updateAuthUI() {
    const authStatus = document.getElementById('auth-status');
    const logoutBtn = document.getElementById('logout-btn');

    if (authStatus) {
        if (currentUser) {
            authStatus.innerHTML = `Logged in as: <strong>${currentUser.username}</strong> (${currentUser.role})`;
            authStatus.className = 'alert alert-success';
        } else {
            authStatus.innerHTML = 'Not logged in';
            authStatus.className = 'alert alert-warning';
        }
    }

    if (logoutBtn) {
        logoutBtn.style.display = currentUser ? 'inline-block' : 'none';
    }
}

async function apiRequest(endpoint, method = 'GET', body = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json'
        }
    };

    if (authToken) {
        options.headers['Authorization'] = `Bearer ${authToken}`;
    }

    if (body) {
        options.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(`${API_BASE}${endpoint}`, options);
        const data = await response.json();
        return { status: response.status, data };
    } catch (error) {
        return { status: 0, data: { error: error.message } };
    }
}

function displayResponse(elementId, response) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = JSON.stringify(response, null, 2);
    }
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type}`;
    notification.textContent = message;
    notification.style.position = 'fixed';
    notification.style.top = '20px';
    notification.style.right = '20px';
    notification.style.zIndex = '1000';
    notification.style.minWidth = '300px';

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// ==================== Authentication ====================

async function login(username, password) {
    const response = await apiRequest('/auth/login', 'POST', { username, password });

    if (response.status === 200) {
        setToken(response.data.token);
        setCurrentUser(response.data.user);
        showNotification('Login successful!', 'success');
    }

    return response;
}

async function register(userData) {
    const response = await apiRequest('/auth/register', 'POST', userData);

    if (response.status === 201) {
        showNotification('Registration successful!', 'success');
    }

    return response;
}

async function logout() {
    clearAuth();
    showNotification('Logged out', 'info');
}

// ==================== Users ====================

async function getUsers() {
    return await apiRequest('/users');
}

async function getUser(userId) {
    return await apiRequest(`/users/${userId}`);
}

async function updateUser(userId, data) {
    return await apiRequest(`/users/${userId}`, 'PUT', data);
}

async function deleteUser(userId) {
    return await apiRequest(`/users/${userId}`, 'DELETE');
}

async function searchUsers(query, field = 'username') {
    return await apiRequest(`/users/search?q=${encodeURIComponent(query)}&field=${field}`);
}

// ==================== Products ====================

async function getProducts() {
    return await apiRequest('/products');
}

async function getProduct(productId) {
    return await apiRequest(`/products/${productId}`);
}

async function createProduct(data) {
    return await apiRequest('/products', 'POST', data);
}

async function updateProduct(productId, data) {
    return await apiRequest(`/products/${productId}`, 'PUT', data);
}

// ==================== Orders ====================

async function getOrders() {
    return await apiRequest('/orders');
}

async function getOrder(orderId) {
    return await apiRequest(`/orders/${orderId}`);
}

async function createOrder(data) {
    return await apiRequest('/orders', 'POST', data);
}

async function updateOrder(orderId, data) {
    return await apiRequest(`/orders/${orderId}`, 'PUT', data);
}

// ==================== Admin ====================

async function getAdminConfig() {
    return await apiRequest('/admin/config');
}

async function getAuditLogs() {
    return await apiRequest('/admin/logs');
}

async function executeRawQuery(query) {
    return await apiRequest('/admin/database/query', 'POST', { query });
}

// ==================== Files/SSRF ====================

async function fetchRemoteUrl(url) {
    return await apiRequest('/files/fetch', 'POST', { url });
}

async function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch(`${API_BASE}/files/upload`, {
            method: 'POST',
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {},
            body: formData
        });
        return { status: response.status, data: await response.json() };
    } catch (error) {
        return { status: 0, data: { error: error.message } };
    }
}

// ==================== Debug ====================

async function getDebugInfo() {
    return await apiRequest('/debug/env');
}

async function getRoutes() {
    return await apiRequest('/debug/routes');
}

async function executeCode(code) {
    return await apiRequest('/debug/execute', 'POST', { code });
}

// ==================== Event Handlers ====================

document.addEventListener('DOMContentLoaded', function() {
    updateAuthUI();

    // Tab functionality
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', function() {
            const tabGroup = this.closest('.tabs').parentElement;
            tabGroup.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            tabGroup.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            this.classList.add('active');
            const targetId = this.getAttribute('data-tab');
            document.getElementById(targetId).classList.add('active');
        });
    });

    // Login form
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            const response = await login(username, password);
            displayResponse('login-response', response);
        });
    }

    // Register form
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const userData = {
                username: document.getElementById('reg-username').value,
                email: document.getElementById('reg-email').value,
                password: document.getElementById('reg-password').value,
                role: document.getElementById('reg-role')?.value || 'user',
                balance: parseFloat(document.getElementById('reg-balance')?.value) || 100
            };
            const response = await register(userData);
            displayResponse('register-response', response);
        });
    }

    // Logout button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }

    // Get users button
    const getUsersBtn = document.getElementById('get-users-btn');
    if (getUsersBtn) {
        getUsersBtn.addEventListener('click', async function() {
            const response = await getUsers();
            displayResponse('users-response', response);
        });
    }

    // Get user by ID
    const getUserBtn = document.getElementById('get-user-btn');
    if (getUserBtn) {
        getUserBtn.addEventListener('click', async function() {
            const userId = document.getElementById('user-id-input').value;
            const response = await getUser(userId);
            displayResponse('user-response', response);
        });
    }

    // Update user form
    const updateUserForm = document.getElementById('update-user-form');
    if (updateUserForm) {
        updateUserForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const userId = document.getElementById('update-user-id').value;
            const data = {};

            const fields = ['role', 'balance', 'password'];
            fields.forEach(field => {
                const input = document.getElementById(`update-${field}`);
                if (input && input.value) {
                    data[field] = field === 'balance' ? parseFloat(input.value) : input.value;
                }
            });

            const response = await updateUser(userId, data);
            displayResponse('update-user-response', response);
        });
    }

    // Get products button
    const getProductsBtn = document.getElementById('get-products-btn');
    if (getProductsBtn) {
        getProductsBtn.addEventListener('click', async function() {
            const response = await getProducts();
            displayResponse('products-response', response);
        });
    }

    // Create order form
    const createOrderForm = document.getElementById('create-order-form');
    if (createOrderForm) {
        createOrderForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const data = {
                product_id: parseInt(document.getElementById('order-product-id').value),
                quantity: parseInt(document.getElementById('order-quantity').value) || 1,
                total_price: parseFloat(document.getElementById('order-price').value) || undefined,
                user_id: parseInt(document.getElementById('order-user-id').value) || undefined
            };
            const response = await createOrder(data);
            displayResponse('order-response', response);
        });
    }

    // Get orders button
    const getOrdersBtn = document.getElementById('get-orders-btn');
    if (getOrdersBtn) {
        getOrdersBtn.addEventListener('click', async function() {
            const response = await getOrders();
            displayResponse('orders-response', response);
        });
    }

    // SSRF fetch form
    const ssrfForm = document.getElementById('ssrf-form');
    if (ssrfForm) {
        ssrfForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const url = document.getElementById('ssrf-url').value;
            const response = await fetchRemoteUrl(url);
            displayResponse('ssrf-response', response);
        });
    }

    // Admin config button
    const adminConfigBtn = document.getElementById('admin-config-btn');
    if (adminConfigBtn) {
        adminConfigBtn.addEventListener('click', async function() {
            const response = await getAdminConfig();
            displayResponse('admin-response', response);
        });
    }

    // Raw query form
    const queryForm = document.getElementById('query-form');
    if (queryForm) {
        queryForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const query = document.getElementById('raw-query').value;
            const response = await executeRawQuery(query);
            displayResponse('query-response', response);
        });
    }

    // Debug info button
    const debugInfoBtn = document.getElementById('debug-info-btn');
    if (debugInfoBtn) {
        debugInfoBtn.addEventListener('click', async function() {
            const response = await getDebugInfo();
            displayResponse('debug-response', response);
        });
    }

    // Routes button
    const routesBtn = document.getElementById('routes-btn');
    if (routesBtn) {
        routesBtn.addEventListener('click', async function() {
            const response = await getRoutes();
            displayResponse('debug-response', response);
        });
    }

    // Code execution form
    const codeForm = document.getElementById('code-form');
    if (codeForm) {
        codeForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const code = document.getElementById('code-input').value;
            const response = await executeCode(code);
            displayResponse('code-response', response);
        });
    }

    // File upload form
    const uploadForm = document.getElementById('upload-form');
    if (uploadForm) {
        uploadForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const fileInput = document.getElementById('file-input');
            if (fileInput.files.length > 0) {
                const response = await uploadFile(fileInput.files[0]);
                displayResponse('upload-response', response);
            }
        });
    }

    // Search users form
    const searchForm = document.getElementById('search-form');
    if (searchForm) {
        searchForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const query = document.getElementById('search-query').value;
            const field = document.getElementById('search-field').value;
            const response = await searchUsers(query, field);
            displayResponse('search-response', response);
        });
    }
});

// Copy to clipboard functionality for code blocks
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Copied to clipboard!', 'success');
    }).catch(err => {
        showNotification('Failed to copy', 'danger');
    });
}

// Export functions for use in HTML
window.VulnAPI = {
    login,
    register,
    logout,
    getUsers,
    getUser,
    updateUser,
    deleteUser,
    searchUsers,
    getProducts,
    getProduct,
    createProduct,
    updateProduct,
    getOrders,
    getOrder,
    createOrder,
    updateOrder,
    getAdminConfig,
    getAuditLogs,
    executeRawQuery,
    fetchRemoteUrl,
    uploadFile,
    getDebugInfo,
    getRoutes,
    executeCode,
    apiRequest,
    displayResponse,
    copyToClipboard
};

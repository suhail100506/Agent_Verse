import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('pramaan_access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      const refreshToken = localStorage.getItem('pramaan_refresh_token');
      if (refreshToken) {
        try {
          const res = await axios.post('/api/auth/refresh', { refresh_token: refreshToken });
          localStorage.setItem('pramaan_access_token', res.data.access_token);
          api.defaults.headers.common['Authorization'] = `Bearer ${res.data.access_token}`;
          return api(originalRequest);
        } catch (refreshErr) {
          localStorage.removeItem('pramaan_access_token');
          localStorage.removeItem('pramaan_refresh_token');
          localStorage.removeItem('pramaan_user');
          window.location.href = '/login';
        }
      }
    }
    return Promise.reject(error);
  }
);

export default api;

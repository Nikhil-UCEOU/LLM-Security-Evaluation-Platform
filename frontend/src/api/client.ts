import axios from 'axios'

const API_KEY = import.meta.env.VITE_API_KEY || 'cortexflow-dev-key'

const client = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY,
  },
})

client.interceptors.response.use(
  (res) => res,
  (error) => {
    const msg = error.response?.data?.detail || error.message || 'Request failed'
    return Promise.reject(new Error(msg))
  }
)

export default client

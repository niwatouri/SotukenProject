import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Signup from './pages/Signup';
import Home from './pages/Home';
import Dashboard from './pages/Dashboard';
import AIAnalysis from './pages/AIAnalysis';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ScanProvider } from './contexts/ScanContext';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />;
}

function App() {
  return (
    <AuthProvider>
      <ScanProvider>
        <Router>
          <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/signup" element={<Signup />} />
              <Route
                path="/home"
                element={
                  <ProtectedRoute>
                    <Home />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/dashboard"
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/ai-analysis"
                element={
                  <ProtectedRoute>
                    <AIAnalysis />
                  </ProtectedRoute>
                }
              />
              <Route path="/" element={<Navigate to="/login" />} />
            </Routes>
          </div>
        </Router>
      </ScanProvider>
    </AuthProvider>
  );
}

export default App;
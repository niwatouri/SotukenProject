import React, { createContext, useContext, useEffect, useState } from 'react';
import { resolveBaseUrl } from '../utils/url';

interface AuthContextType {
  isAuthenticated: boolean;
  user: { email: string } | null;
  login: (email: string, password: string) => Promise<boolean>;
  signup: (email: string, password: string, confirmPassword: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);
const AUTH_BASE_URL = resolveBaseUrl(import.meta.env.VITE_AUTH_URL, 'http://localhost:3000');
// ローカルストレージを使ってリロード後も状態を維持し、Cookie設定の差異を避ける。
const TOKEN_STORAGE_KEY = 'auth_token';

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<{ email: string } | null>(null);

  useEffect(() => {
    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!token) {
      return;
    }

    let isActive = true;

    const restoreSession = async () => {
      try {
        const response = await fetch(`${AUTH_BASE_URL}/me`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (!response.ok) {
          throw new Error('Unauthorized');
        }

        const data = await response.json();
        const email = data?.user?.email;
        if (!email) {
          throw new Error('Invalid user payload');
        }

        if (!isActive) {
          return;
        }

        setIsAuthenticated(true);
        setUser({ email });
      } catch (err) {
        localStorage.removeItem(TOKEN_STORAGE_KEY);
        if (!isActive) {
          return;
        }
        setIsAuthenticated(false);
        setUser(null);
      }
    };

    restoreSession();

    return () => {
      isActive = false;
    };
  }, []);

  const login = async (email: string, password: string): Promise<boolean> => {
    try {
      const response = await fetch(`${AUTH_BASE_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        // 401や500エラー
        return false;
      }

      const data = await response.json();
      if (!data?.token) {
        return false;
      }

      localStorage.setItem(TOKEN_STORAGE_KEY, data.token);
      setIsAuthenticated(true);
      setUser({ email: data.user?.email ?? email });
      return true;
    } catch (err) {
      console.error('ログインエラー:', err);
      return false;
    }
  };

  const signup = async (email: string, password: string, confirmPassword: string): Promise<{ success: boolean; error?: string }> => {
    if (!email || !password || !confirmPassword) {
      return { success: false, error: 'すべてのフィールドを入力してください' };
    }
    if (password !== confirmPassword) {
      return { success: false, error: 'パスワードが一致しません' };
    }
    if (password.length < 8) {
      return { success: false, error: 'パスワードは8文字以上で入力してください' };
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return { success: false, error: '有効なメールアドレスを入力してください' };
    }

    try {
      const response = await fetch(`${AUTH_BASE_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const data = await response.json();
        return { success: false, error: data.error || '登録に失敗しました' };
      }

      const data = await response.json();
      if (!data?.token) {
        return { success: false, error: '登録に失敗しました' };
      }

      localStorage.setItem(TOKEN_STORAGE_KEY, data.token);
      setIsAuthenticated(true);
      setUser({ email: data.user?.email ?? email });
      return { success: true };
    } catch (error) {
      return { success: false, error: 'サーバーに接続できませんでした' };
    }
  };

  const logout = () => {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    setIsAuthenticated(false);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, login, signup, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

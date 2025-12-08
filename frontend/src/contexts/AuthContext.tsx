import React, { createContext, useContext, useState } from 'react';

interface AuthContextType {
  isAuthenticated: boolean;
  user: { email: string } | null;
  login: (email: string, password: string) => Promise<boolean>;
  signup: (email: string, password: string, confirmPassword: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<{ email: string } | null>(null);

  const login = async (email: string, password: string): Promise<boolean> => {
    try {
      const response = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        // 401や500エラー
        return false;
      }

      const data = await response.json();
      console.log('ログイン成功:', data);

      setIsAuthenticated(true);
      setUser({ email }); // 実際は data.user を使うとより良い
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
      const response = await fetch('http://localhost:3000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const data = await response.json();
        return { success: false, error: data.error || '登録に失敗しました' };
      }

      // 登録成功時
      setIsAuthenticated(true);
      setUser({ email });
      return { success: true };
    } catch (error) {
      return { success: false, error: 'サーバーに接続できませんでした' };
    }
  };

  const logout = () => {
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

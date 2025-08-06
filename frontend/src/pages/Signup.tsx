import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Lock, Mail, AlertCircle, CheckCircle } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import TermsModal from '../components/TermsModal';

function Signup() {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showTerms, setShowTerms] = useState(false);
  const [acceptedTerms, setAcceptedTerms] = useState(false);
  const { signup } = useAuth();
  const navigate = useNavigate();

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const getPasswordStrength = (password: string) => {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    return strength;
  };

  const getPasswordStrengthText = (strength: number) => {
    switch (strength) {
      case 0:
      case 1: return { text: '弱い', color: 'text-red-600' };
      case 2: return { text: '普通', color: 'text-orange-600' };
      case 3: return { text: '良い', color: 'text-yellow-600' };
      case 4:
      case 5: return { text: '強い', color: 'text-green-600' };
      default: return { text: '', color: '' };
    }
  };

  const passwordStrength = getPasswordStrength(formData.password);
  const strengthInfo = getPasswordStrengthText(passwordStrength);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!acceptedTerms) {
      setShowTerms(true);
      return;
    }

    setIsLoading(true);
    const result = await signup(formData.email, formData.password, formData.confirmPassword);
    setIsLoading(false);

    if (result.success) {
      navigate('/home');
    } else {
      setError(result.error || 'アカウント作成に失敗しました');
    }
  };

  const handleTermsAccept = () => {
    setAcceptedTerms(true);
    setShowTerms(false);
  };

  const handleTermsClose = () => {
    setShowTerms(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 p-4">
      <div className="w-full max-w-md">
        <div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-2xl p-8 border border-white/20">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-r from-blue-600 to-purple-600 mb-4">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">SecureGuard</h1>
            <p className="text-gray-600">新規アカウント作成</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                メールアドレス
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => handleInputChange('email', e.target.value)}
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                  placeholder="your@email.com"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                パスワード
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="password"
                  value={formData.password}
                  onChange={(e) => handleInputChange('password', e.target.value)}
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                  placeholder="••••••••"
                />
              </div>
              {formData.password && (
                <div className="mt-2">
                  <div className="flex items-center space-x-2">
                    <div className="flex-1 bg-gray-200 rounded-full h-2">
                     <div
                        className={`h-2 rounded-full transition-all duration-300 ${
                          passwordStrength <= 1 ? 'bg-red-500' :
                          passwordStrength === 2 ? 'bg-orange-500' :
                          passwordStrength === 3 ? 'bg-yellow-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${(passwordStrength / 5) * 100}%` }}
                      ></div>
                    </div>
                    <span className={`text-xs font-medium ${strengthInfo.color}`}>
                      {strengthInfo.text}
                    </span>
                  </div>
                  <div className="mt-2 text-xs text-gray-600 space-y-1">
                    <div className="flex items-center space-x-2">
                      {formData.password.length >= 8 ? (
                        <CheckCircle className="w-3 h-3 text-green-500" />
                      ) : (
                        <div className="w-3 h-3 border border-gray-300 rounded-full"></div>
                      )}
                      <span>8文字以上</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      {/[A-Z]/.test(formData.password) ? (
                        <CheckCircle className="w-3 h-3 text-green-500" />
                      ) : (
                        <div className="w-3 h-3 border border-gray-300 rounded-full"></div>
                      )}
                      <span>大文字を含む</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      {/[0-9]/.test(formData.password) ? (
                        <CheckCircle className="w-3 h-3 text-green-500" />
                      ) : (
                        <div className="w-3 h-3 border border-gray-300 rounded-full"></div>
                      )}
                      <span>数字を含む</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                パスワード確認
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="password"
                  value={formData.confirmPassword}
                  onChange={(e) => handleInputChange('confirmPassword', e.target.value)}
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                  placeholder="••••••••"
                />
                {formData.confirmPassword && (
                  <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                    {formData.password === formData.confirmPassword ? (
                      <CheckCircle className="w-5 h-5 text-green-500" />
                    ) : (
                      <AlertCircle className="w-5 h-5 text-red-500" />
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Terms Agreement Status */}
            <div className={`p-4 rounded-lg border-2 transition-all ${
            acceptedTerms 
              ? 'bg-green-50 border-green-200' 
              : 'bg-blue-50 border-blue-200'
             }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={acceptedTerms}
                    onChange={() => {}}
                    className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                    disabled
                  />
                  <span className={`text-sm font-medium ${acceptedTerms ? 'text-green-900' : 'text-blue-900'}`}>
                    {acceptedTerms ? '利用規約に同意済み' : '利用規約への同意が必要です'}
                  </span>
                </div>
                {!acceptedTerms && (
                  <button
                    type="button"
                    onClick={() => setShowTerms(true)}
                    className="text-sm text-blue-600 hover:text-blue-700 font-medium underline"
                  >
                    規約を確認
                  </button>
                )}
              </div>
            </div>

            {error && (
              <div className="flex items-center space-x-2 text-red-600 bg-red-50 p-3 rounded-lg">
                <AlertCircle className="w-5 h-5" />
                <span className="text-sm">{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-3 px-4 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-medium rounded-lg hover:from-blue-700 hover:to-purple-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'アカウント作成中...' : 'アカウント作成'}
            </button>
          </form>

          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600">
              すでにアカウントをお持ちの方は{' '}
              <Link
                to="/login"
                className="text-blue-600 hover:text-blue-700 font-medium transition-colors"
              >
                ログイン
              </Link>
            </p>
          </div>

          <div className="mt-4 text-center text-xs text-gray-500">
            Demo: 有効なメールアドレス形式と8文字以上のパスワードで登録できます
          </div>
        </div>
      </div>

      <TermsModal
        isOpen={showTerms}
        onClose={handleTermsClose}
        onAccept={handleTermsAccept}
      />
    </div>
  );
}

export default Signup;
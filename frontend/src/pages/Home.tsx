import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Globe, Settings, Scan, AlertTriangle, LogOut, User } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useScan, ScanAuthConfig } from '../contexts/ScanContext';
import ScanConfirmModal from '../components/ScanConfirmModal';
import Footer from '../components/Footer';

// dotlottie-player はWeb Componentsなので基本import不要
// もし動かなければ npm install @dotlottie/react-player してください

function Home() {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState<'bulk' | 'detailed'>('bulk');
  const [scanOptions, setScanOptions] = useState({
    sqlInjection: true,
    directoryTraversal: true,
    xss: true,
    portScan: true,
  });
  const [useAuthScan, setUseAuthScan] = useState(false);
  const [authMethod, setAuthMethod] = useState<'form' | 'cookie' | 'header'>('form');
  const [formAuth, setFormAuth] = useState({
    loginUrl: '',
    username: '',
    password: '',
    loginIndicator: '',
    usernameField: 'username',
    passwordField: 'password',
    extraParams: '',
    loginRequestData: '',
  });
  const [cookieAuth, setCookieAuth] = useState({ cookie: '' });
  const [headerAuth, setHeaderAuth] = useState({ header: '' });
  const [error, setError] = useState('');
  const [showConfirmModal, setShowConfirmModal] = useState(false);

  // --- スピナー用ランダムアニメーションURL ---
  const [animationUrl, setAnimationUrl] = useState('');
  const animationLinks = [
    'https://lottie.host/106c06df-90cc-4491-857e-b9479e8e32c2/9qpvz0cF2h.lottie',
    'https://lottie.host/e2ec55e0-e408-423d-ba9a-4c961d75c0fb/wij0MCcBhJ.lottie',
    'https://lottie.host/db8ac7eb-bac5-44b7-8cba-1dd62709bbd7/ZpQYKJ913h.lottie',
    'https://lottie.host/8f0daed4-722b-48e6-b8f5-f9bd87323f86/6F5eWt0D55.lottie',
    'https://lottie.host/95b4247c-307c-4d63-be35-ff735f0ad16c/NJKtHZT9V5.lottie',
    'https://lottie.host/95d55f3f-c151-4b0f-be85-0beb562f8b75/06LlRW7dCN.lottie',
    'https://lottie.host/96206794-804f-492d-a804-9f1f7bd0c4a9/244DkcPTre.lottie',
    'https://lottie.host/6f2dcbc4-bb0a-47c8-8fc8-c1f9dc28b115/NgqQI1CHX1.lottie',
  ];

  useEffect(() => {
    const randomIndex = Math.floor(Math.random() * animationLinks.length);
    setAnimationUrl(animationLinks[randomIndex]);
  }, []);

  // ----------------------------------------

  const { logout, user } = useAuth();
  const { startScan, isScanning, scanProgress } = useScan();
  const navigate = useNavigate();

  const handleScanOptionChange = (option: keyof typeof scanOptions) => {
    setScanOptions(prev => ({
      ...prev,
      [option]: !prev[option]
    }));
  };

  const handleScanClick = () => {
    setError('');

    if (!targetUrl) {
      setError('スキャン対象のURLを入力してください');
      return;
    }

    try {
      new URL(targetUrl);
    } catch {
      setError('有効なURL形式で入力してください（例: https://example.com）');
      return;
    }

    if (scanType === 'detailed') {
      const selectedOptions = Object.entries(scanOptions).filter(([_, enabled]) => enabled);
      if (selectedOptions.length === 0) {
        setError('詳細スキャンでは少なくとも1つのオプションを選択してください');
        return;
      }
    }

    setShowConfirmModal(true);
  };

  const handleConfirmScan = async () => {
    setShowConfirmModal(false);

    const optionCodes = {
      sqlInjection: 'sqli',
      directoryTraversal: 'path_traversal',
      xss: 'xss',
      portScan: 'port_scan',
    };

    const selectedScanTypes = scanType === 'detailed'
      ? Object.entries(scanOptions)
          .filter(([_, enabled]) => enabled)
          .map(([key]) => optionCodes[key as keyof typeof optionCodes])
          .filter(Boolean)
      : ['all'];

    let authPayload: ScanAuthConfig = null;
    if (scanType === 'detailed' && useAuthScan) {
      if (authMethod === 'form') {
        if (!formAuth.loginUrl || !formAuth.username || !formAuth.password) {
          setError('フォーム認証のURL・ユーザー名・パスワードを入力してください');
          return;
        }
        authPayload = {
          method: 'form',
          login_url: formAuth.loginUrl,
          username: formAuth.username,
          password: formAuth.password,
          login_indicator: formAuth.loginIndicator || undefined,
          username_field: formAuth.usernameField || undefined,
          password_field: formAuth.passwordField || undefined,
          extra_params: formAuth.extraParams || undefined,
          login_request_data: formAuth.loginRequestData || undefined,
        };
      } else if (authMethod === 'cookie') {
        if (!cookieAuth.cookie) {
          setError('セッションCookieを入力してください');
          return;
        }
        authPayload = {
          method: 'cookie',
          cookie: cookieAuth.cookie,
        };
      } else {
        if (!headerAuth.header) {
          setError('Authorizationヘッダの値を入力してください');
          return;
        }
        authPayload = {
          method: 'header',
          header: headerAuth.header,
        };
      }
    }

    const success = await startScan(targetUrl, selectedScanTypes, authPayload);
    if (success) {
      navigate('/dashboard');
    }
  };

  const getSelectedOptions = () => {
    const optionNames = {
      sqlInjection: 'SQL Injection',
      directoryTraversal: 'Directory Traversal',
      xss: 'XSS',
      portScan: 'Open Port'
    };

    return Object.entries(scanOptions)
      .filter(([_, enabled]) => enabled)
      .map(([key, _]) => optionNames[key as keyof typeof optionNames]);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex flex-col">

      {/* スキャン中スピナー */}
      {isScanning && (
        <div className="fixed top-0 left-0 w-screen h-screen bg-white flex justify-center items-center z-[9999] flex-col">
          <dotlottie-player
            src={animationUrl}
            background="transparent"
            speed="1"
            loop
            autoplay
            style={{ width: '300px', height: '300px' }}
          ></dotlottie-player>
          <p className="load mt-4 text-lg font-medium text-gray-700">スキャン中・・・</p>
          <div className="mt-8 w-80">
            <div className="h-3 w-full rounded-full bg-gray-200">
              <div
                className="h-3 rounded-full bg-blue-600 transition-all"
                style={{ width: `${scanProgress}%` }}
              ></div>
            </div>
            <p className="mt-3 text-center text-base text-gray-600">{scanProgress}%</p>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm border-b border-slate-200 sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-full bg-gradient-to-r from-blue-600 to-purple-600">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-900">SecureGuard</h1>
              <p className="text-sm text-gray-600">脆弱性スキャナー</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2 text-sm text-gray-600">
              <User className="w-4 h-4" />
              <span>{user?.email}</span>
            </div>
            <button
              onClick={logout}
              className="flex items-center space-x-2 px-3 py-2 text-sm text-gray-600 hover:text-red-600 transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span>ログアウト</span>
            </button>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-4xl mx-auto px-4 py-8">
        <div className="text-center mb-8">
          <h2 className="text-3xl font-bold text-gray-900 mb-4">セキュリティスキャン</h2>
          <p className="text-lg text-gray-600">Webサイトの脆弱性を検出し、セキュリティリスクを評価します</p>
        </div>

        <div className="bg-white rounded-2xl shadow-xl p-8 border border-slate-200">
          <div className="space-y-8">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-3">スキャン対象URL</label>
              <div className="relative">
                <Globe className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="url"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-4">スキャンタイプ</label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div
                  onClick={() => setScanType('bulk')}
                  className={`p-6 border-2 rounded-xl cursor-pointer transition-all ${scanType === 'bulk' ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'}`}
                >
                  <div className="flex items-center space-x-3 mb-3">
                    <Scan className={`w-6 h-6 ${scanType === 'bulk' ? 'text-blue-600' : 'text-gray-600'}`} />
                    <h3 className={`text-lg font-semibold ${scanType === 'bulk' ? 'text-blue-900' : 'text-gray-900'}`}>一括スキャン</h3>
                  </div>
                  <p className="text-sm text-gray-600">すべての脆弱性を包括的にスキャンします。初回スキャンに推奨です。</p>
                </div>

                <div
                  onClick={() => setScanType('detailed')}
                  className={`p-6 border-2 rounded-xl cursor-pointer transition-all ${scanType === 'detailed' ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'}`}
                >
                  <div className="flex items-center space-x-3 mb-3">
                    <Settings className={`w-6 h-6 ${scanType === 'detailed' ? 'text-blue-600' : 'text-gray-600'}`} />
                    <h3 className={`text-lg font-semibold ${scanType === 'detailed' ? 'text-blue-900' : 'text-gray-900'}`}>詳細スキャン</h3>
                  </div>
                  <p className="text-sm text-gray-600">特定の脆弱性タイプを選択してスキャンします。</p>
                </div>
              </div>
            </div>

            {scanType === 'detailed' && (
              <div className="bg-slate-50 rounded-xl p-6">
                <h4 className="text-lg font-semibold text-gray-900 mb-4">スキャンオプション</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {[{ key: 'sqlInjection', label: 'SQLインジェクション', description: 'データベースへの不正アクセス' },
                    { key: 'directoryTraversal', label: 'ディレクトリトラバーサル', description: 'ファイルシステムへの不正アクセス' },
                    { key: 'xss', label: 'XSS (クロスサイトスクリプティング)', description: 'スクリプト実行攻撃' },
                    { key: 'portScan', label: 'ポートスキャン', description: '開放ポートの検出' }].map(({ key, label, description }) => (
                    <label key={key} className="flex items-start space-x-3 p-3 bg-white rounded-lg cursor-pointer hover:bg-gray-50 transition-colors">
                      <input
                        type="checkbox"
                        checked={scanOptions[key as keyof typeof scanOptions]}
                        onChange={() => handleScanOptionChange(key as keyof typeof scanOptions)}
                        className="w-5 h-5 text-blue-600 border-gray-300 rounded focus:ring-blue-500 mt-0.5"
                      />
                      <div>
                        <div className="font-medium text-gray-900">{label}</div>
                        <div className="text-sm text-gray-600">{description}</div>
                      </div>
                    </label>
                  ))}
                </div>

                <div className="mt-8 border-t border-slate-200 pt-6">
                  <h4 className="text-lg font-semibold text-gray-900 mb-4">認証設定</h4>
                  <div className="flex items-center space-x-6 mb-4">
                    <label className="flex items-center space-x-2 text-sm text-gray-700">
                      <input
                        type="radio"
                        name="useAuth"
                        checked={!useAuthScan}
                        onChange={() => setUseAuthScan(false)}
                        className="w-4 h-4 text-blue-600 border-gray-300"
                      />
                      <span>認証を使わない</span>
                    </label>
                    <label className="flex items-center space-x-2 text-sm text-gray-700">
                      <input
                        type="radio"
                        name="useAuth"
                        checked={useAuthScan}
                        onChange={() => setUseAuthScan(true)}
                        className="w-4 h-4 text-blue-600 border-gray-300"
                      />
                      <span>認証を使う</span>
                    </label>
                  </div>

                  {useAuthScan && (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">認証方式</label>
                        <select
                          value={authMethod}
                          onChange={(e) => setAuthMethod(e.target.value as 'form' | 'cookie' | 'header')}
                          className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        >
                          <option value="form">フォーム認証</option>
                          <option value="cookie">セッションCookie</option>
                          <option value="header">Authorizationヘッダ</option>
                        </select>
                      </div>

                      {authMethod === 'form' && (
                        <div className="grid grid-cols-1 gap-4">
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">ログインURL</label>
                            <input
                              type="url"
                              value={formAuth.loginUrl}
                              onChange={(e) => setFormAuth(prev => ({ ...prev, loginUrl: e.target.value }))}
                              placeholder="https://example.com/login"
                              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">ユーザー名</label>
                            <input
                              type="text"
                              value={formAuth.username}
                              onChange={(e) => setFormAuth(prev => ({ ...prev, username: e.target.value }))}
                              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">パスワード</label>
                            <input
                              type="password"
                              value={formAuth.password}
                              onChange={(e) => setFormAuth(prev => ({ ...prev, password: e.target.value }))}
                              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">ログイン成功判定（任意）</label>
                            <input
                              type="text"
                              value={formAuth.loginIndicator}
                              onChange={(e) => setFormAuth(prev => ({ ...prev, loginIndicator: e.target.value }))}
                              placeholder="例: Logout"
                              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                            <p className="text-xs text-gray-500 mt-1">ログイン成功後のHTMLに含まれる文字列を指定します。</p>
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">ユーザー名フィールド名（任意）</label>
                            <input
                              type="text"
                              value={formAuth.usernameField}
                              onChange={(e) => setFormAuth(prev => ({ ...prev, usernameField: e.target.value }))}
                              placeholder="username"
                              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">パスワードフィールド名（任意）</label>
                            <input
                              type="text"
                              value={formAuth.passwordField}
                              onChange={(e) => setFormAuth(prev => ({ ...prev, passwordField: e.target.value }))}
                              placeholder="password"
                              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">追加パラメータ（任意）</label>
                            <input
                              type="text"
                              value={formAuth.extraParams}
                              onChange={(e) => setFormAuth(prev => ({ ...prev, extraParams: e.target.value }))}
                              placeholder="csrf=xxxx&remember=1"
                              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                            <p className="text-xs text-gray-500 mt-1">必要な場合のみ、フォーム送信パラメータを追加します。</p>
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">loginRequestData 直接指定（任意）</label>
                            <input
                              type="text"
                              value={formAuth.loginRequestData}
                              onChange={(e) => setFormAuth(prev => ({ ...prev, loginRequestData: e.target.value }))}
                              placeholder="username=%username%&password=%password%&csrf=xxxx"
                              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                            <p className="text-xs text-gray-500 mt-1">上級者向け。入力するとフィールド名/追加パラメータより優先されます。</p>
                          </div>
                        </div>
                      )}

                      {authMethod === 'cookie' && (
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">セッションCookie</label>
                          <input
                            type="text"
                            value={cookieAuth.cookie}
                            onChange={(e) => setCookieAuth({ cookie: e.target.value })}
                            placeholder="SESSIONID=abc123; Path=/; HttpOnly"
                            className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          />
                        </div>
                      )}

                      {authMethod === 'header' && (
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">Authorizationヘッダ値</label>
                          <input
                            type="text"
                            value={headerAuth.header}
                            onChange={(e) => setHeaderAuth({ header: e.target.value })}
                            placeholder="Bearer xxxxx"
                            className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          />
                        </div>
                      )}

                      <p className="text-xs text-gray-500">
                        認証情報はスキャン実行中のみ使用され、保存されません。
                      </p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {error && (
              <div className="flex items-center space-x-3 p-4 bg-red-50 border border-red-200 rounded-lg">
                <AlertTriangle className="w-5 h-5 text-red-600" />
                <span className="text-red-800">{error}</span>
              </div>
            )}

            <button
              onClick={handleScanClick}
              disabled={isScanning}
              className="w-full py-4 px-6 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-xl hover:from-blue-700 hover:to-purple-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-3"
            >
              <Scan className="w-5 h-5" />
              <span>{isScanning ? 'キュー投入/スキャン中...' : 'スキャン開始'}</span>
            </button>
          </div>
        </div>
      </main>

      <Footer />

      <ScanConfirmModal
        isOpen={showConfirmModal}
        onClose={() => setShowConfirmModal(false)}
        onConfirm={handleConfirmScan}
        targetUrl={targetUrl}
        scanType={scanType}
        selectedOptions={scanType === 'detailed' ? getSelectedOptions() : undefined}
      />
    </div>
  );
}

export default Home;

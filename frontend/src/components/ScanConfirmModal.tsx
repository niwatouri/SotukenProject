import React, { useState } from 'react';
import { AlertTriangle, Shield, X } from 'lucide-react';

interface ScanConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  targetUrl: string;
  scanType: 'bulk' | 'detailed';
  selectedOptions?: string[];
}

function ScanConfirmModal({ isOpen, onClose, onConfirm, targetUrl, scanType, selectedOptions }: ScanConfirmModalProps) {
  const [agreed, setAgreed] = useState(false);

  if (!isOpen) return null;

  const handleConfirm = () => {
    if (agreed) {
      onConfirm();
      setAgreed(false); // Reset for next time
    }
  };

  const optionLabels: Record<string, string> = {
    'SQL Injection': 'SQLインジェクション',
    'Directory Traversal': 'ディレクトリトラバーサル',
    'XSS': 'XSS (クロスサイトスクリプティング)',
    'Open Port': 'ポートスキャン'
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-2xl shadow-2xl max-w-2xl w-full max-h-screen overflow-y-auto">
        <div className="bg-gradient-to-r from-orange-500 to-red-500 text-white p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <AlertTriangle className="w-8 h-8" />
              <div>
                <h2 className="text-2xl font-bold">診断実行の確認</h2>
                <p className="text-orange-100">重要な確認事項があります</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/20 rounded-lg transition-colors"
            >
              <X className="w-6 h-6" />
            </button>
          </div>
        </div>

        <div className="p-6">
          <div className="mb-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">診断対象情報</h3>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-600 mb-1">対象URL:</p>
              <p className="font-medium text-gray-900 mb-3">{targetUrl}</p>
              <p className="text-sm text-gray-600 mb-1">診断タイプ:</p>
              <p className="font-medium text-gray-900 mb-3">
                {scanType === 'bulk' ? '一括スキャン' : '詳細スキャン'}
              </p>
              {scanType === 'detailed' && selectedOptions && selectedOptions.length > 0 && (
                <>
                  <p className="text-sm text-gray-600 mb-1">スキャン対象:</p>
                  <div className="flex flex-wrap gap-2">
                    {selectedOptions.map((option) => (
                      <span
                        key={option}
                        className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-sm font-medium"
                      >
                        {optionLabels[option] || option}
                      </span>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>

          <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg mb-6">
            <div className="flex items-start space-x-3">
              <Shield className="w-6 h-6 text-red-600 mt-1" />
              <div>
                <h4 className="text-lg font-semibold text-red-900 mb-3">重要な注意事項</h4>
                <ul className="text-red-800 text-sm space-y-2">
                  <li>• <strong>自分が管理・許可を持つシステムのみ</strong>を診断対象としてください</li>
                  <li>• 他者のシステムへの無断スキャンは<strong>不正アクセス禁止法違反</strong>となる可能性があります</li>
                  <li>• 診断結果の責任は利用者が負います</li>
                  <li>• システム障害やデータ損失が発生しても当社は責任を負いません</li>
                </ul>
              </div>
            </div>
          </div>

          <div className="bg-blue-50 border border-blue-200 p-4 rounded-lg mb-6">
            <label className="flex items-start space-x-3 cursor-pointer">
              <input
                type="checkbox"
                checked={agreed}
                onChange={(e) => setAgreed(e.target.checked)}
                className="w-5 h-5 text-blue-600 border-gray-300 rounded focus:ring-blue-500 mt-1"
              />
              <div>
                <span className="text-blue-900 font-medium">
                  自分の管理するシステムに対してのみ診断します
                </span>
                <p className="text-blue-800 text-sm mt-1">
                  上記の注意事項を理解し、適切な権限を持つシステムのみを診断対象とすることを確認します。
                </p>
              </div>
            </label>
          </div>

          <div className="flex justify-end space-x-3">
            <button
              onClick={onClose}
              className="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-100 transition-colors"
            >
              キャンセル
            </button>
            <button
              onClick={handleConfirm}
              disabled={!agreed}
              className="px-6 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg hover:from-blue-700 hover:to-purple-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              診断を開始
            </button>
          </div>
        </div>
      </div>
    </div >
  );
}

export default ScanConfirmModal;
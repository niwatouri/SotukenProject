import React from 'react';
import { X, Shield, AlertTriangle, Lock, FileText } from 'lucide-react';

interface TermsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAccept: () => void;
}

function TermsModal({ isOpen, onClose, onAccept }: TermsModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-2xl shadow-2xl max-w-4xl max-h-[90vh] overflow-hidden">
        <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8" />
              <div>
                <h2 className="text-2xl font-bold">脆弱性診断ツール利用規約</h2>
                <p className="text-blue-100">ご利用前に必ずお読みください</p>
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

        <div className="p-6 overflow-y-auto max-h-[60vh]">
          <div className="space-y-8">
            {/* 利用目的・対象システム */}
            <section>
              <div className="flex items-center space-x-3 mb-4">
                <FileText className="w-6 h-6 text-blue-600" />
                <h3 className="text-xl font-bold text-gray-900">1. 利用目的・対象システム</h3>
              </div>
              <div className="bg-blue-50 border-l-4 border-blue-500 p-4 rounded-r-lg mb-4">
                <p className="text-blue-900 font-medium mb-2">利用目的の制限</p>
                <ul className="text-blue-800 text-sm space-y-1">
                  <li>• 利用目的は教育・セキュリティ向上限定とし、業務外の攻撃目的や商用利用は禁止します</li>
                  <li>• 学内ユーザーが学習や自組織のセキュリティ強化のためにのみ使用するものとします</li>
                </ul>
              </div>
              <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg">
                <p className="text-red-900 font-medium mb-2">診断対象の制限</p>
                <ul className="text-red-800 text-sm space-y-1">
                  <li>• 診断対象は利用者自身が管理・許可を持つシステムのみとします</li>
                  <li>• 他部門・他人・外部サイトなどのシステムへの無断スキャンは禁止します</li>
                  <li>• 管理者や所有者の承諾なしに行う診断行為は、不正アクセス禁止法に抵触する可能性があるため厳禁です</li>
                  <li>• 対象システムの範囲は明確にし、許可を得たテスト用環境以外は絶対に操作しないでください</li>
                </ul>
              </div>
            </section>

            {/* アカウント管理 */}
            <section>
              <div className="flex items-center space-x-3 mb-4">
                <Lock className="w-6 h-6 text-green-600" />
                <h3 className="text-xl font-bold text-gray-900">2. アカウント管理</h3>
              </div>
              <div className="bg-gray-50 p-4 rounded-lg">
                <ul className="text-gray-800 text-sm space-y-2">
                  <li>• 本ツールの利用には学内発行のID/PWによるログインが必要です</li>
                  <li>• ユーザーは自分のアカウント情報を厳重に管理し、第三者と共有・共用してはなりません</li>
                  <li>• アカウントは善良な管理者としての注意義務をもって保管し、不正利用を防止する責任があります</li>
                  <li>• アカウントの不正使用等により当社または第三者に損害が生じた場合、当該ユーザーがその賠償責任を負います</li>
                  <li>• 当社は、ユーザー設定のアカウントから行われた利用は全てそのユーザー本人によるものとみなし、第三者による不正利用によって発生した損害については一切責任を負いません</li>
                </ul>
              </div>
            </section>

            {/* 診断に関する責任・免責 */}
            <section>
              <div className="flex items-center space-x-3 mb-4">
                <AlertTriangle className="w-6 h-6 text-orange-600" />
                <h3 className="text-xl font-bold text-gray-900">3. 診断（スキャン）に関する責任・免責</h3>
              </div>
              <div className="bg-orange-50 border border-orange-200 p-4 rounded-lg">
                <ul className="text-orange-900 text-sm space-y-2">
                  <li>• ツールによる診断結果は参考情報です。全ての脆弱性を必ず検出するものではなく、検出漏れや誤検知が生じる可能性があることをユーザーは了承してください</li>
                  <li>• ユーザーは診断結果を踏まえて自ら評価・対応を行う責任があり、当社は検出精度・分析結果の正確性や完全性を保証しません</li>
                  <li>• 診断中および診断後にシステム障害やデータ損失が発生しても、当社は一切の責任を負わないものとします</li>
                  <li>• ユーザーは事前に対象システムのバックアップを取得し、ツール利用によるリスクを自己責任で管理してください</li>
                  <li>• 診断結果や脆弱性情報は機密情報とみなし、関係者以外に開示しないこととします。情報漏洩があった場合の責任は全てユーザー側にあります</li>
                </ul>
              </div>
            </section>

            {/* 法令・ガイドラインの遵守 */}
            <section>
              <div className="flex items-center space-x-3 mb-4">
                <Shield className="w-6 h-6 text-purple-600" />
                <h3 className="text-xl font-bold text-gray-900">4. 法令・ガイドラインの遵守</h3>
              </div>
              <div className="bg-purple-50 border border-purple-200 p-4 rounded-lg">
                <ul className="text-purple-900 text-sm space-y-2">
                  <li>• 本規約および診断に関しては、不正アクセス禁止法をはじめ関連法令を遵守してください</li>
                  <li>• 不正アクセス禁止法では、管理者の許可がないアクセス行為は違法とされます（管理者承諾下のテスト行為は規制対象外です）</li>
                  <li>• 診断実施にあたっては、IPA「安全なウェブサイトの作り方」やOWASPのガイドライン等、セキュリティベストプラクティスを参照し、適切な手順と倫理規範に則って行ってください</li>
                  <li>• 利用規約違反や法令違反があった場合は、利用停止・アカウント削除などの措置を取る場合があります</li>
                  <li>• 最悪の場合、法的手段による対応が必要になることも利用者は承知の上、責任を負うものとします</li>
                </ul>
              </div>
            </section>
          </div>
        </div>

        <div className="bg-gray-50 p-6 border-t border-gray-200">
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-600">
              上記の利用規約をよくお読みいただき、同意いただける場合は「同意する」ボタンをクリックしてください。
            </p>
            <div className="flex space-x-3">
              <button
                onClick={onClose}
                className="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-100 transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={onAccept}
                className="px-6 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg hover:from-blue-700 hover:to-purple-700 transition-all"
              >
                同意する
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default TermsModal;
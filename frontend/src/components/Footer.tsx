import React, { useState } from 'react';
import { Shield, FileText } from 'lucide-react';
import TermsModal from './TermsModal';

function Footer() {
  const [showTerms, setShowTerms] = useState(false);

  return (
    <>
      <footer className="bg-white border-t border-gray-200 mt-auto">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="w-5 h-5 text-blue-600" />
              <span className="text-sm text-gray-600">SecureGuard - 脆弱性スキャナー</span>
            </div>
            
            <div className="flex items-center space-x-6">
              <button
                onClick={() => setShowTerms(true)}
                className="flex items-center space-x-2 text-sm text-gray-600 hover:text-blue-600 transition-colors"
              >
                <FileText className="w-4 h-4" />
                <span>利用規約</span>
              </button>
              <span className="text-xs text-gray-500">
                © 2024 SecureGuard. Educational use only.
              </span>
            </div>
          </div>
        </div>
      </footer>

      <TermsModal
        isOpen={showTerms}
        onClose={() => setShowTerms(false)}
        onAccept={() => setShowTerms(false)}
      />
    </>
  );
}

export default Footer;
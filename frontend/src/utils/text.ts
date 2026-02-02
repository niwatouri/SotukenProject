export const stripHtml = (value: string) => {
  if (!value) {
    return '';
  }

  const withoutTags = value.replace(/<[^>]*>/g, ' ');
  const decoded = withoutTags
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'");

  return decoded.replace(/\s+/g, ' ').trim();
};

export const AI_GENERAL_LABEL = '※この提案は一般的な対策です（アプリの技術スタックにより最適解は異なります）';

const AI_TECH_REPLACEMENTS: Array<[RegExp, string]> = [
  [/\bJDBC\b/gi, 'DB接続'],
  [/\bPreparedStatement\b/gi, 'プレースホルダ/バインド変数'],
  [/\bCallableStatement\b/gi, 'ストアドプロシージャ呼び出し'],
  [/\bJPA\b/gi, 'ORM'],
  [/\bHibernate\b/gi, 'ORM'],
];

export const normalizeAiText = (value: string) => {
  if (!value) {
    return '';
  }
  let text = stripHtml(value);
  AI_TECH_REPLACEMENTS.forEach(([pattern, replacement]) => {
    text = text.replace(pattern, replacement);
  });
  return text;
};

export const normalizeAiSteps = (steps: string[]) => {
  if (!Array.isArray(steps)) {
    return [];
  }
  return steps.map((step) => normalizeAiText(step)).filter((step) => step.length > 0);
};

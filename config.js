// 公開してよい値だけを置く（GitHub Pages で誰でも読める）。秘匿値・子のデータは置かない（DEC-077）。
//   apiUrl   … GAS Web App の /exec（全ての操作の前に ID トークンと閲覧者リストを確かめる）
//   clientId … Google の OAuth クライアント ID（ID トークンの宛先。GAS の Script Property GOOGLE_OAUTH_CLIENT_ID と同じ値）
window.GINA_CONFIG = {
  apiUrl: 'https://script.google.com/macros/s/AKfycbwV9ijnqGJbOL-Mx7LB1LMKheFwXo-dYVDxWTRYLltI3aiI6BooNK20HknuGPEJAbxq2w/exec',
  clientId: '519518787927-rie1r96cjd1ffe5vrpi2474b10m63u0i.apps.googleusercontent.com'
};

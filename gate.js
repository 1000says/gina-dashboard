// ============================================================
// gate.js — ログインと API 呼び出し（GitHub Pages のダッシュボード・DEC-077）
//
// 流れ: Google でログイン（Google Identity Services）→ ID トークン（1 時間で切れる・本アプリ宛て）
//   → GAS の JSON API へ POST（text/plain＝プリフライトを起こさない単純リクエスト）→ 画面へ渡す。
// トークンはタブを閉じると消える sessionStorage にだけ置く（localStorage に残さない）。
// 期限が近い・切れた・拒否されたら、ログインの画面へ戻して同じ操作をやり直す。
//
// 判断の部分（期限・応答の分類・JWT の読み取り）は純粋関数にして node から検査する（tests/verify_local.js）。
// ============================================================
(function (root) {
  'use strict';

  var TOKEN_KEY = 'gina.idToken';
  var EXP_MARGIN_SEC = 120;   // 残り 2 分を切ったトークンは使わない（往復の間に切れるのを避ける）

  /** base64url → 文字列（UTF-8）。ブラウザでも node でも動く。 */
  function b64urlDecode(s) {
    var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    if (typeof atob === 'function') {
      var bin = atob(b64);
      try { return decodeURIComponent(bin.split('').map(function (c) { return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2); }).join('')); } catch (e) { return bin; }
    }
    return Buffer.from(b64, 'base64').toString('utf8');
  }

  /** JWT の payload（署名は見ない＝期限と表示用の email を読むだけ。検証はサーバが行う）。 */
  function readClaims(token) {
    if (typeof token !== 'string') return null;
    var p = token.split('.');
    if (p.length !== 3) return null;
    try { return JSON.parse(b64urlDecode(p[1])); } catch (e) { return null; }
  }

  /** まだ使えるトークンか（純粋関数）。 */
  function tokenUsable(token, nowSec) {
    var c = readClaims(token);
    return !!(c && typeof c.exp === 'number' && c.exp - EXP_MARGIN_SEC > nowSec);
  }

  /**
   * API の応答を分類する（純粋関数）。
   * @return {'ok'|'login'|'denied'|'readonly'|'error'}
   *   login＝トークンが無い・切れた・不正（ログインし直せば通る）
   *   denied＝本人確認はできたが閲覧者リストに無い（ログインし直しても通らない）
   */
  function classifyResponse(res) {
    if (!res || typeof res !== 'object') return 'error';
    if (res.ok === true) return 'ok';
    if (res.reason === 'auth_required') return 'login';
    if (res.reason === 'not_allowed') return 'denied';
    // T-452: 公開の閲覧者（閲覧者リストに無い人）が書く・設定の操作をした＝ログアウトさせない
    if (res.reason === 'read_only') return 'readonly';
    return 'error';
  }

  /** POST の本文（純粋関数）。 */
  function buildRequest(token, action, args) {
    return JSON.stringify({ kind: 'gina-api', idToken: token, action: action, args: args || [] });
  }

  // ---- ブラウザだけ ----
  var state = { token: null, waiters: [], onDenied: null, ui: null };

  function storeToken(t) {
    state.token = t;
    try { root.sessionStorage.setItem(TOKEN_KEY, t); } catch (e) { /* 保存できなくても今の画面は使える */ }
  }
  function loadToken() {
    if (state.token) return state.token;
    try { state.token = root.sessionStorage.getItem(TOKEN_KEY); } catch (e) { state.token = null; }
    return state.token;
  }
  function clearToken() {
    state.token = null;
    try { root.sessionStorage.removeItem(TOKEN_KEY); } catch (e) { /* noop */ }
  }
  function nowSec() { return Math.floor(Date.now() / 1000); }

  /** 使えるトークンを待つ（無ければログインの画面を出す）。 */
  function needToken(reason) {
    var t = loadToken();
    if (t && tokenUsable(t, nowSec())) return Promise.resolve(t);
    clearToken();
    return new Promise(function (resolve) {
      state.waiters.push(resolve);
      if (state.ui) state.ui.showLogin(reason || 'start');
    });
  }

  /** GIS からトークンを受け取った（ログインのボタン・自動ログイン）。 */
  function onCredential(resp) {
    if (!resp || !resp.credential) return;
    storeToken(resp.credential);
    if (state.ui) state.ui.hideLogin();
    var w = state.waiters; state.waiters = [];
    w.forEach(function (fn) { fn(resp.credential); });
  }

  /**
   * サーバの操作を呼ぶ。ログインが要れば待ってからやり直す（1 回まで）。
   * @return {Promise<*>} 操作の戻り値（result）。拒否・失敗は reject（Error.reason に分類）
   */
  function call(action, args, retried) {
    var cfg = root.GINA_CONFIG || {};
    return needToken(retried ? 'expired' : 'start').then(function (token) {
      return fetch(cfg.apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
        body: buildRequest(token, action, args),
        redirect: 'follow',
        credentials: 'omit',
        cache: 'no-store'
      }).then(function (r) { return r.json(); });
    }).then(function (res) {
      var kind = classifyResponse(res);
      if (kind === 'ok') return res.result;
      if (kind === 'login' && !retried) { clearToken(); return call(action, args, true); }
      if (kind === 'denied' && state.ui) state.ui.showDenied(res.email || '');
      var err = new Error(kind);
      err.reason = kind;
      throw err;
    });
  }

  /**
   * google.script.run と同じ書き方で call を呼ぶ互換部品。
   *   google.script.run.withSuccessHandler(f).withFailureHandler(g).saveSetting(k, v)
   * 名前を限らずに受けるが、呼べるのはサーバの allowlist（api.js の apiActions_）にある操作だけ。
   */
  function makeRunner(onOk, onErr) {
    return new Proxy({}, {
      get: function (_t, name) {
        if (name === 'withSuccessHandler') return function (f) { return makeRunner(f, onErr); };
        if (name === 'withFailureHandler') return function (g) { return makeRunner(onOk, g); };
        if (typeof name !== 'string') return undefined;
        return function () {
          var args = Array.prototype.slice.call(arguments);
          call(name, args).then(function (r) { if (onOk) onOk(r); }, function (e) { if (onErr) onErr(e); });
        };
      }
    });
  }

  /** window.google.script.run を用意する（GIS が後から window.google を作っても消えないよう両方で呼ぶ）。 */
  function installRunner() {
    root.google = root.google || {};
    if (!root.google.script) root.google.script = { run: makeRunner(null, null) };
  }

  /** GIS を初期化する（スクリプトの読み込みを待つ）。 */
  function initGis(buttonEl) {
    var cfg = root.GINA_CONFIG || {};
    var tries = 0;
    (function wait() {
      var g = root.google && root.google.accounts && root.google.accounts.id;
      if (!g) { if (tries++ < 100) return setTimeout(wait, 100); if (state.ui) state.ui.showError('gis'); return; }
      installRunner();
      g.initialize({ client_id: cfg.clientId, callback: onCredential, auto_select: true, cancel_on_tap_outside: false,
        use_fedcm_for_prompt: true, itp_support: true });
      if (buttonEl) g.renderButton(buttonEl, { type: 'standard', theme: 'filled_blue', size: 'large', text: 'signin_with', shape: 'pill', locale: 'ja' });
      if (!tokenUsable(loadToken(), nowSec())) g.prompt();
    })();
  }

  function signOut() {
    clearToken();
    try { root.google.accounts.id.disableAutoSelect(); } catch (e) { /* noop */ }
  }

  var api = {
    readClaims: readClaims, tokenUsable: tokenUsable, classifyResponse: classifyResponse, buildRequest: buildRequest,
    EXP_MARGIN_SEC: EXP_MARGIN_SEC,
    call: call, installRunner: installRunner, initGis: initGis, signOut: signOut,
    currentEmail: function () { var c = readClaims(loadToken()); return (c && c.email) || ''; },
    setUi: function (ui) { state.ui = ui; }
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GinaGate = api;
})(typeof window !== 'undefined' ? window : globalThis);

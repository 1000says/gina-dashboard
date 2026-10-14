// ============================================================
// gate.js — ログインと API 呼び出し（GitHub Pages のダッシュボード・DEC-077）
//
// 流れ: Google でログイン（Google Identity Services）→ ID トークン（1 時間で切れる・本アプリ宛て）
//   → GAS の JSON API へ POST（text/plain＝プリフライトを起こさない単純リクエスト）→ 画面へ渡す。
// トークンはタブを閉じると消える sessionStorage にだけ置く（localStorage に残さない）。
// 期限が近い・切れた・拒否されたら、ログインの画面へ戻して同じ操作をやり直す。
//
// 【ログインを 1 回にまとめる（2026-10-15）】
//   ①開いている別のタブが使えるトークンを持っていれば、それを受け取る（BroadcastChannel・同じオリジンだけ）。
//     置き場は sessionStorage のまま＝ディスクに長く残る場所へは広げない。
//   ②無ければ、Chrome にログイン中の Google アカウントで自動ログインする（GIS の auto_select・FedCM）。
//     ボタンは、自動で取れなかったとき（数秒待っても来ない・Google が出さないと決めた）だけ出す。
//   ③切れる少し前に、画面を見ている間だけ自動で取り直す（1 時間ごとにボタンを押させない）。
//     取り直すのはタブ 1 つだけ（Web Locks）・トークン 1 つにつき 1 回まで。Chrome の自動ログインは 10 分に 1 回で、
//     2 つ目のタブが同時に試すと選択画面になるため。結果は他のタブへ配る。
//   【受け取らないもの（G3 2026-10-15）】サーバに断られたトークン（端末の時計のずれ・client ID の変更）／
//     今のタブと別のアカウント（sub が違う）／ログアウトより前に発行されたトークン。
//     ログアウトの時刻だけは localStorage に置く（秘密ではない数値。通知を受け損ねたタブが戻ってきても、
//     古いトークンを配り直さないため）。トークン自体は localStorage に置かない。
//
// 判断の部分（期限・応答の分類・JWT の読み取り）は純粋関数にして node から検査する（tests/verify_local.js）。
// ============================================================
(function (root) {
  'use strict';

  var TOKEN_KEY = 'gina.idToken';
  var EXP_MARGIN_SEC = 120;   // 残り 2 分を切ったトークンは使わない（往復の間に切れるのを避ける）
  var REFRESH_LEAD_SEC = 300; // 使えなくなる 5 分前に自動で取り直す
  var SILENT_WAIT_MS = 3000;  // 自動ログインを待つ時間。過ぎたらボタンを出す（自動はそのまま待ち続ける）
  var ASK_WAIT_MS = 300;      // 別のタブの返事を待つ時間。返事が来れば Google の自動ログインを使わない
                              //   （Chrome の自動ログインは 10 分に 1 回まで＝無駄に使うと次はボタンになる）
  var CHANNEL_NAME = 'gina.auth';
  var SIGNOUT_KEY = 'gina.signedOutAt';   // ログアウトした時刻（UNIX 秒）。秘密ではない
  var LOCK_NAME = 'gina.signin';

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

  /**
   * ログアウトより後に発行され、サーバに断られていないトークンか（純粋関数）。
   * @param {{rejected:(Array<string>|undefined), signedOutAt:(number|undefined)}} ctx
   */
  function tokenTrusted(token, ctx) {
    var c = readClaims(token);
    if (!c) return false;
    var x = ctx || {};
    if (x.rejected && x.rejected.indexOf(token) >= 0) return false;
    if (x.signedOutAt && !(typeof c.iat === 'number' && c.iat > x.signedOutAt)) return false;
    return true;
  }

  /**
   * 別のタブから届いたトークンを使うか（純粋関数）。使えて・信頼でき・同じアカウントで、今のものより長く使えるときだけ。
   * @param {{sub:(string|undefined), rejected:(Array<string>|undefined), signedOutAt:(number|undefined)}} ctx
   * @return {boolean}
   */
  function shouldAdopt(current, incoming, nowSec, ctx) {
    var x = ctx || {};
    if (!tokenUsable(incoming, nowSec) || !tokenTrusted(incoming, x)) return false;
    if (x.sub && readClaims(incoming).sub !== x.sub) return false;   // 黙って別のアカウントへ切り替えない
    if (!tokenUsable(current, nowSec)) return true;
    return readClaims(incoming).exp > readClaims(current).exp;
  }

  /**
   * 自動で取り直すまでの待ち時間（ミリ秒・純粋関数）。使えなくなる REFRESH_LEAD_SEC 前。既に過ぎていれば 0。
   * @return {?number} トークンが読めなければ null
   */
  function refreshDelayMs(token, nowSec) {
    var c = readClaims(token);
    if (!c || typeof c.exp !== 'number') return null;
    return Math.max(0, (c.exp - EXP_MARGIN_SEC - REFRESH_LEAD_SEC - nowSec) * 1000);
  }

  /** POST の本文（純粋関数）。 */
  function buildRequest(token, action, args) {
    return JSON.stringify({ kind: 'gina-api', idToken: token, action: action, args: args || [] });
  }

  // ---- ブラウザだけ ----
  var state = { token: null, waiters: [], ui: null, gis: null, channel: null, refreshTimer: null,
    signingIn: false, fallbackTimer: null, promptPending: false, sub: null, rejected: [], refreshedFor: null,
    lockRelease: null };

  function storeToken(t) {
    state.token = t;
    try { root.sessionStorage.setItem(TOKEN_KEY, t); } catch (e) { /* 保存できなくても今の画面は使える */ }
  }
  function loadToken() {
    if (!state.token) {
      try { state.token = root.sessionStorage.getItem(TOKEN_KEY); } catch (e) { state.token = null; }
    }
    // 別のタブでログアウトした・サーバに断られた＝このタブが通知を受け損ねていても使わない
    if (state.token && !tokenTrusted(state.token, trustCtx())) clearToken();
    if (state.token && !state.sub) state.sub = (readClaims(state.token) || {}).sub || null;
    return state.token;
  }
  function clearToken() {
    state.token = null;
    try { root.sessionStorage.removeItem(TOKEN_KEY); } catch (e) { /* noop */ }
  }
  function nowSec() { return Math.floor(Date.now() / 1000); }
  function signedOutAt() {
    try { return Number(root.localStorage.getItem(SIGNOUT_KEY)) || 0; } catch (e) { return 0; }
  }
  function trustCtx() { return { sub: state.sub, rejected: state.rejected, signedOutAt: signedOutAt() }; }
  /** サーバに断られたトークンを覚えて、このタブでも他のタブでも使わない。 */
  function rejectToken(t, share) {
    if (!t || state.rejected.indexOf(t) >= 0) return;
    state.rejected.push(t);
    if (state.rejected.length > 20) state.rejected.shift();
    if (state.token === t) clearToken();
    if (share) post({ t: 'reject', token: t });
  }
  /** Web Locks がある時だけ、取り直すタブを 1 つに絞る。無ければそのまま試す。 */
  function withSignInLock(fn) {
    var locks = root.navigator && root.navigator.locks;
    if (!locks || typeof locks.request !== 'function') { fn(); return; }
    locks.request(LOCK_NAME, { ifAvailable: true }, function (lock) {
      if (!lock) return null;   // 他のタブが取り直し中＝その結果が届くのを待つ（届かなければボタン）
      return new Promise(function (release) {
        state.lockRelease = release;
        setTimeout(releaseLock, SILENT_WAIT_MS * 3);   // Google から返らなくても握り続けない
        fn();
      });
    });
  }
  function releaseLock() { if (state.lockRelease) { var r = state.lockRelease; state.lockRelease = null; r(); } }

  /** 別のタブとの受け渡し（同じオリジンだけに届く）。使えないブラウザでは何もしない。 */
  function openChannel() {
    if (state.channel || typeof root.BroadcastChannel !== 'function') return state.channel;
    try { state.channel = new root.BroadcastChannel(CHANNEL_NAME); } catch (e) { state.channel = null; return null; }
    state.channel.onmessage = function (ev) {
      var m = ev && ev.data;
      if (!m || typeof m !== 'object') return;
      if (m.t === 'ask') {
        var mine = loadToken();
        if (tokenUsable(mine, nowSec())) post({ t: 'token', token: mine });
      } else if (m.t === 'token' && typeof m.token === 'string') {
        if (shouldAdopt(loadToken(), m.token, nowSec(), trustCtx())) acceptToken(m.token, false);
      } else if (m.t === 'reject' && typeof m.token === 'string') {
        rejectToken(m.token, false);
      } else if (m.t === 'signout') {
        forget();
        if (state.ui) state.ui.showLogin('signedout', false);   // 記録を出したままにしない・理由を言う
      }
    };
    return state.channel;
  }
  function post(msg) {
    var ch = openChannel();
    if (ch) { try { ch.postMessage(msg); } catch (e) { /* noop */ } }
  }

  /** 使えるトークンを受け取った（自動・ボタン・別のタブ）。待っている呼び出しを全部進める。 */
  function acceptToken(token, share) {
    storeToken(token);
    state.sub = (readClaims(token) || {}).sub || null;
    releaseLock();
    state.signingIn = false;
    clearTimeout(state.fallbackTimer);
    if (share) post({ t: 'token', token: token });
    scheduleRefresh(token);
    if (state.ui) state.ui.hideLogin();
    var w = state.waiters; state.waiters = [];
    w.forEach(function (fn) { fn(token); });
  }

  /** GIS の自動ログインを試す（auto_select）。Google が出さないと決めたら、すぐボタンを出す。 */
  function promptSilently() {
    if (!state.gis) { state.promptPending = true; return; }   // GIS の読み込みを待って initGis が呼ぶ
    state.promptPending = false;
    withSignInLock(function () {
      // 待っている間に別のタブが取り直していれば、Google の自動ログインを使わない
      var t = loadToken();
      if (tokenUsable(t, nowSec()) && refreshDelayMs(t, nowSec()) > 0) { releaseLock(); return; }
      try {
        state.gis.prompt(function (n) {
          // FedCM では表示のモーメント（isNotDisplayed）は届かない。skipped だけが確かな「出さない」の合図
          var skipped = n && typeof n.isSkippedMoment === 'function' && n.isSkippedMoment();
          if (skipped) { releaseLock(); if (state.signingIn) showButton(); }
        });
      } catch (e) { releaseLock(); if (state.signingIn) showButton(); }
    });
  }

  function showButton() {
    clearTimeout(state.fallbackTimer);
    if (state.ui) state.ui.showLogin(state.signingIn === 'expired' ? 'expired' : 'start', false);
  }

  /** ログインを始める（1 回だけ）: 別のタブに聞く → 自動ログイン → 待っても来なければボタン。 */
  function beginSignIn(reason, skipAsk) {
    if (state.signingIn) return;
    state.signingIn = reason === 'expired' ? 'expired' : 'start';
    if (state.ui) state.ui.showLogin(state.signingIn, true);
    clearTimeout(state.fallbackTimer);
    state.fallbackTimer = setTimeout(function () { if (state.signingIn) showButton(); }, SILENT_WAIT_MS);
    if (!skipAsk && openChannel()) {
      post({ t: 'ask' });
      setTimeout(function () { if (state.signingIn) promptSilently(); }, ASK_WAIT_MS);
    } else {
      promptSilently();
    }
  }

  /** 切れる前に、画面を見ている間だけ自動で取り直す。見ていなければ、次に画面へ戻ったときに取り直す。 */
  function scheduleRefresh(token) {
    clearTimeout(state.refreshTimer);
    var ms = refreshDelayMs(token, nowSec());
    if (ms === null) return;
    state.refreshTimer = setTimeout(function () {
      var doc = root.document;
      if (doc && doc.visibilityState === 'hidden') return;   // visibilitychange で取り直す
      refreshOnce();
    }, ms);
  }
  /** 今のトークンにつき 1 回だけ、裏で取り直す。 */
  function refreshOnce() {
    var t = loadToken();
    if (!t || state.refreshedFor === t) return;
    state.refreshedFor = t;
    promptSilently();
  }
  function onVisible() {
    var doc = root.document;
    if (!doc || doc.visibilityState !== 'visible') return;
    var t = loadToken();
    var ms = refreshDelayMs(t, nowSec());
    if (ms === 0 && !state.signingIn) {
      if (tokenUsable(t, nowSec())) refreshOnce();      // まだ使える＝裏で取り直す
      else beginSignIn('expired');                       // 切れた＝次の呼び出しを待たずに取りに行く
    }
  }

  /** 使えるトークンを待つ（無ければログインを始める）。 */
  function needToken(reason, skipAsk) {
    var t = loadToken();
    if (t && tokenUsable(t, nowSec())) return Promise.resolve(t);
    clearToken();
    return new Promise(function (resolve) {
      state.waiters.push(resolve);
      beginSignIn(reason || 'start', skipAsk);
    });
  }

  /** GIS からトークンを受け取った（ボタン・自動ログイン）。 */
  function onCredential(resp) {
    if (!resp || !resp.credential) return;
    acceptToken(resp.credential, true);
  }

  /**
   * サーバの操作を呼ぶ。ログインが要れば待ってからやり直す（1 回まで）。
   * @return {Promise<*>} 操作の戻り値（result）。拒否・失敗は reject（Error.reason に分類）
   */
  function call(action, args, retried) {
    var cfg = root.GINA_CONFIG || {};
    // やり直し（断られた後）は他のタブに聞かない＝同じトークンが返ってくるだけ
    return needToken(retried ? 'expired' : 'start', !!retried).then(function (token) {
      return fetch(cfg.apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
        body: buildRequest(token, action, args),
        redirect: 'follow',
        credentials: 'omit',
        cache: 'no-store'
      }).then(function (r) { return r.json(); }).then(function (res) { return { res: res, token: token }; });
    }).then(function (o) {
      var res = o.res;
      var kind = classifyResponse(res);
      if (kind === 'ok') return res.result;
      // 断られたトークンは覚えて、他のタブにも使わせない（並んで飛んだ呼び出しが先に取り直した新しいトークンは消さない）
      if (kind === 'login' || kind === 'denied') rejectToken(o.token, true);
      if (kind === 'login' && !retried) return call(action, args, true);
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
    openChannel();
    var t0 = loadToken();
    if (tokenUsable(t0, nowSec())) scheduleRefresh(t0);
    if (root.document && root.document.addEventListener) root.document.addEventListener('visibilitychange', onVisible);
    (function wait() {
      var g = root.google && root.google.accounts && root.google.accounts.id;
      if (!g) { if (tries++ < 100) return setTimeout(wait, 100); if (state.ui) state.ui.showError('gis'); return; }
      installRunner();
      // use_fedcm_for_button: ボタンでのログインも FedCM を通す。通さないと Chrome が「このサイトで使ったアカウント」と
      //   覚えず、次から自動の再ログイン（auto_select）が効かない（OI-104 G2 MUST-1・2026-10-15）。
      // button_auto_select: ボタンを押したとき、戻ってきた人は選択画面を飛ばす。
      g.initialize({ client_id: cfg.clientId, callback: onCredential, auto_select: true, cancel_on_tap_outside: false,
        use_fedcm_for_prompt: true, use_fedcm_for_button: true, button_auto_select: true, itp_support: true });
      if (buttonEl) g.renderButton(buttonEl, { type: 'standard', theme: 'filled_blue', size: 'large', text: 'signin_with', shape: 'pill', locale: 'ja' });
      state.gis = g;
      if (state.promptPending) promptSilently();
    })();
  }

  /** このタブのログイン状態を消す（他のタブへは伝えない）。 */
  function forget() {
    clearToken();
    clearTimeout(state.refreshTimer);
    state.sub = null;
    state.refreshedFor = null;
  }

  /**
   * ログアウト。localOnly＝このタブだけ（登録されていないアカウントで入ったとき＝他のタブの正しいログインは消さない）。
   */
  function signOut(localOnly) {
    forget();
    if (!localOnly) {
      try { root.localStorage.setItem(SIGNOUT_KEY, String(nowSec())); } catch (e) { /* noop */ }
      post({ t: 'signout' });
    }
    try { root.google.accounts.id.disableAutoSelect(); } catch (e) { /* noop */ }
  }

  var api = {
    readClaims: readClaims, tokenUsable: tokenUsable, classifyResponse: classifyResponse, buildRequest: buildRequest,
    shouldAdopt: shouldAdopt, tokenTrusted: tokenTrusted, refreshDelayMs: refreshDelayMs,
    EXP_MARGIN_SEC: EXP_MARGIN_SEC, REFRESH_LEAD_SEC: REFRESH_LEAD_SEC,
    call: call, installRunner: installRunner, initGis: initGis, signOut: signOut,
    currentEmail: function () { var c = readClaims(loadToken()); return (c && c.email) || ''; },
    setUi: function (ui) { state.ui = ui; }
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GinaGate = api;
})(typeof window !== 'undefined' ? window : globalThis);

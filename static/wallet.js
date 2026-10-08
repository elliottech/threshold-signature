// Shared header wallet widget: connect/disconnect MetaMask and remember the account for the tab.
// Pages can override window.onWalletConnect / window.onWalletDisconnect for extra behavior.
(function () {
  const $ = (id) => document.getElementById(id);
  const short = (a) => a.slice(0, 6) + '…' + a.slice(-4);

  function renderWallet() {
    const a = window.walletAccount;
    if ($('wallet')) $('wallet').style.display = a ? '' : 'none';
    if ($('walletAddr') && a) $('walletAddr').textContent = short(a);
    if ($('connect')) $('connect').style.display = a ? 'none' : '';
    if ($('disconnect')) $('disconnect').style.display = a ? '' : 'none';
  }

  window.walletAccount = sessionStorage.getItem('tsig-account') || null;

  window.connectWallet = async function () {
    if (!window.ethereum) { alert('MetaMask not found — install it to join a ceremony.'); return null; }
    const accs = await window.ethereum.request({ method: 'eth_requestAccounts' });
    window.walletAccount = accs[0].toLowerCase();
    sessionStorage.setItem('tsig-account', window.walletAccount);
    renderWallet();
    if (window.onWalletConnect) window.onWalletConnect(window.walletAccount);
    return window.walletAccount;
  };

  window.disconnectWallet = function () {
    window.walletAccount = null;
    sessionStorage.removeItem('tsig-account');
    renderWallet();
    if (window.onWalletDisconnect) window.onWalletDisconnect();
  };

  document.addEventListener('DOMContentLoaded', () => {
    if ($('connect')) $('connect').onclick = () => window.connectWallet();
    if ($('disconnect')) $('disconnect').onclick = () => window.disconnectWallet();
    renderWallet();
  });
})();

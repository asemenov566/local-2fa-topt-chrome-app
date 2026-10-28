// A short-lived port per file operation. There is no resident native connection.
export function nativeFile(request) {
  return new Promise((resolve,reject) => {
    let port, finished = false, text = '';
    const timer = setTimeout(() => finish(new Error('Файловый помощник не ответил. Повторите действие.')),request.op === 'pick' ? 302000 : 32000);
    function finish(error,result) {
      if (finished) return; finished = true; clearTimeout(timer);
      try { port?.disconnect(); } catch {}
      error ? reject(error) : resolve(result);
    }
    try {
      port = chrome.runtime.connectNative('com.asemenov566.chrome_app_totp');
      port.onMessage.addListener(message => {
        if (typeof message?.chunk === 'string') {
          text += message.chunk;
          if (text.length > 8000000) finish(new Error('База превышает 8 МБ.'));
        } else if (message?.ok) finish(null,{...message,data:message.exists ? text : null});
        else finish(new Error(message?.error || 'Не удалось обратиться к файлу базы.'));
      });
      port.onDisconnect.addListener(() => {
        const error = chrome.runtime.lastError;
        if (!finished) finish(new Error(error ? 'Не подключён файловый помощник. Один раз запустите Install-Windows.cmd из папки приложения и нажмите «Повторить». Это не фоновая служба.' : 'Файловый помощник завершился до окончания операции.'));
      });
      port.postMessage(request);
    } catch { finish(new Error('Не удалось запустить файловый помощник. Запустите Install-Windows.cmd из папки приложения.')); }
  });
}

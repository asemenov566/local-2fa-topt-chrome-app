export function createQRReader() {
  let worker = null, sequence = 0, closed = false;
  const pending = new Map();
  function close(reason = new DOMException('Сканирование остановлено.','AbortError')) {
    closed = true; worker?.terminate(); worker = null;
    for (const {reject,timer} of pending.values()) { clearTimeout(timer); reject(reason); }
    pending.clear();
  }
  function decode(image,details = false,enhance = false) {
    if (closed) return Promise.reject(new DOMException('Сканирование остановлено.','AbortError'));
    if (!worker) {
      worker = new Worker(new URL('./vendor/qr-reader.js',import.meta.url));
      worker.onmessage = ({data}) => {
        const task = pending.get(data.id); if (!task) return;
        pending.delete(data.id); clearTimeout(task.timer);
        if (data.error) task.reject(new Error(data.error)); else task.resolve(task.details ? {values:data.values,detected:data.detected} : data.values);
      };
      worker.onerror = () => close(new Error('Не удалось запустить локальный сканер QR. Перезагрузите расширение.'));
    }
    // No frame queue: a caller must await the previous decode.
    if (pending.size) return Promise.reject(new Error('Обработка QR уже выполняется.'));
    const id = ++sequence;
    return new Promise((resolve,reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error('Обработка QR заняла слишком много времени.')); close(); },15000);
      pending.set(id,{resolve,reject,timer,details});
      worker.postMessage({id,pixels:image.data.buffer,width:image.width,height:image.height,details,enhance},[image.data.buffer]);
    });
  }
  return {decode,close};
}

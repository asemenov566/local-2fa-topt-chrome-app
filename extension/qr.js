import {createQRReader} from './qr-reader.js';
export async function scanFile(file,signal) {
  if (file.size > 15 * 1024 * 1024) throw new Error('Изображение больше 15 МБ. Обрежьте скриншот вокруг QR.');
  if (!['image/png','image/jpeg','image/webp','image/bmp'].includes(file.type)) throw new Error('Нужен PNG, JPG, WebP или BMP.');
  const reader = createQRReader();
  const abort = () => reader.close(); signal?.addEventListener('abort',abort,{once:true});
  let bitmap;
  try {
    if (signal?.aborted) throw new DOMException('Сканирование остановлено.','AbortError');
    try { bitmap = await createImageBitmap(file); } catch { throw new Error('Не удалось открыть изображение.'); }
    if (signal?.aborted) throw new DOMException('Сканирование остановлено.','AbortError');
    if (bitmap.width * bitmap.height > 40000000) throw new Error('Изображение слишком большое. Обрежьте его вокруг QR.');
    const canvas = document.createElement('canvas'), ctx = canvas.getContext('2d',{willReadFrequently:true});
    const results = new Set();
    for (const maxSide of [1600,3200]) {
      const scale = Math.min(1,maxSide / Math.max(bitmap.width,bitmap.height));
      canvas.width = Math.round(bitmap.width * scale); canvas.height = Math.round(bitmap.height * scale);
      ctx.drawImage(bitmap,0,0,canvas.width,canvas.height);
      const pixels = ctx.getImageData(0,0,canvas.width,canvas.height);
      for (const value of await reader.decode(pixels)) results.add(value);
      if (results.size || scale === 1) break;
      await new Promise(resolve => setTimeout(resolve,0));
    }
    if (!results.size) throw new Error('QR не найден. Попробуйте чёткий скриншот или обрежьте область вокруг QR.');
    return [...results];
  } finally { bitmap?.close(); reader.close(); signal?.removeEventListener('abort',abort); }
}
export function cameraError(e) {
  return ({NotAllowedError:'Доступ к камере запрещён. Разрешите камеру для страницы расширения в настройках Chrome и Windows либо импортируйте фото.',NotFoundError:'Камера не найдена. Подключите её или выберите файл QR.',NotReadableError:'Камера занята другим приложением или недоступна. Закройте его и повторите.',OverconstrainedError:'Выбранная камера недоступна. Выберите другую.',SecurityError:'Chrome запретил использование камеры. Откройте расширение в отдельной вкладке.'})[e.name] || 'Не удалось включить камеру. Попробуйте другую камеру или файл QR.';
}

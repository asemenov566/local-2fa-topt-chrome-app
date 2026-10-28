import {prepareZXingModule,readBarcodes} from 'zxing-wasm/reader';
// Only the bundled module is loaded. No QR image or decoded content leaves the worker.
prepareZXingModule({overrides:{locateFile:() => new URL('./zxing_reader.wasm',self.location.href).href}});
self.onmessage = async ({data:{id,pixels,width,height,details,enhance}}) => {
  try {
    const image = new ImageData(new Uint8ClampedArray(pixels),width,height);
    const options = {
      formats:['QRCode'],tryHarder:true,tryRotate:true,tryInvert:true,tryDownscale:true,
      textMode:'Plain',maxNumberOfSymbols:30,returnErrors:!!details,
    };
    let results = await readBarcodes(image,options);
    const detected = results.length > 0;
    // At most one extra pass. The caller throttles enlarged camera scans to 1 / 2 s.
    if (details && !results.some(r => r.isValid && r.text.trim())) {
      if (enhance) {
        const side = Math.min(width,height,1080), canvas = new OffscreenCanvas(side * 3,side * 3);
        const ctx = canvas.getContext('2d',{willReadFrequently:true}), bitmap = await createImageBitmap(image);
        try {
          ctx.imageSmoothingEnabled = true; ctx.imageSmoothingQuality = 'high';
          ctx.drawImage(bitmap,(width-side)/2,(height-side)/2,side,side,0,0,side*3,side*3);
          results = await readBarcodes(ctx.getImageData(0,0,side*3,side*3),{...options,tryDownscale:false});
        } finally { bitmap.close(); canvas.width = canvas.height = 0; }
      } else if (detected) results = await readBarcodes(image,{...options,tryDenoise:true});
    }
    self.postMessage({id,detected:detected || results.length > 0,values:[...new Set(results.filter(r => r.isValid && r.text.trim()).map(r => r.text))]});
  } catch { self.postMessage({id,error:'Не удалось обработать кадр QR. Попробуйте ещё раз.'}); }
};

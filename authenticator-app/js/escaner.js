// Lectura de códigos QR con la cámara usando la API nativa BarcodeDetector.
// La imagen se analiza en el dispositivo; no se guarda ni se envía.

let flujo = null;
let activo = false;
let temporizador = 0;

/** Indica si el navegador puede leer QR con la cámara. */
export async function escanerDisponible() {
  if (!('BarcodeDetector' in globalThis) || !navigator.mediaDevices?.getUserMedia) return false;
  try {
    const formatos = await globalThis.BarcodeDetector.getSupportedFormats();
    return formatos.includes('qr_code');
  } catch {
    return false;
  }
}

/**
 * Enciende la cámara trasera y busca un QR cada 150 ms.
 * @param {HTMLVideoElement} video
 * @param {(texto: string) => void} alDetectar
 */
export async function iniciarEscaner(video, alDetectar) {
  detenerEscaner(video);
  const detector = new globalThis.BarcodeDetector({ formats: ['qr_code'] });
  flujo = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
  video.srcObject = flujo;
  await video.play();
  activo = true;

  const ciclo = async () => {
    if (!activo) return;
    try {
      if (video.readyState >= 2) {
        const resultados = await detector.detect(video);
        const qr = resultados.find((r) => /^otpauth:/i.test(r.rawValue ?? '')) ?? resultados[0];
        if (qr?.rawValue && activo) {
          detenerEscaner(video);
          alDetectar(qr.rawValue);
          return;
        }
      }
    } catch {
      /* fotograma ilegible: se reintenta */
    }
    temporizador = setTimeout(ciclo, 150);
  };
  ciclo();
}

/** Apaga la cámara y libera el flujo de video. */
export function detenerEscaner(video) {
  activo = false;
  clearTimeout(temporizador);
  if (flujo) for (const pista of flujo.getTracks()) pista.stop();
  flujo = null;
  if (video) video.srcObject = null;
}

export function escaneando() {
  return activo;
}

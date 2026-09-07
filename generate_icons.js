// generate_icons.js - Generates crisp PNG icons for CA Indicator states
// Zero external dependencies, pure Node.js using built-in zlib.

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// Ensure icons directory exists
const iconsDir = path.join(__dirname, 'icons');
if (!fs.existsSync(iconsDir)) {
  fs.mkdirSync(iconsDir, { recursive: true });
}

// Minimal PNG encoder
function createPNG(width, height, pixelData) {
  // pixelData is Buffer of RGBA values (width * height * 4)
  const rowBytes = width * 4;
  const rawRows = Buffer.alloc(height * (rowBytes + 1));

  for (let y = 0; y < height; y++) {
    rawRows[y * (rowBytes + 1)] = 0; // Filter: None
    pixelData.copy(rawRows, y * (rowBytes + 1) + 1, y * rowBytes, (y + 1) * rowBytes);
  }

  const compressed = zlib.deflateSync(rawRows);

  const crcTable = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    crcTable[i] = c;
  }

  function crc32(buf) {
    let crc = -1;
    for (let i = 0; i < buf.length; i++) {
      crc = (crc >>> 8) ^ crcTable[(crc ^ buf[i]) & 0xFF];
    }
    return (crc ^ -1) >>> 0;
  }

  function makeChunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const typeBuf = Buffer.from(type, 'ascii');
    const crcBuf = Buffer.alloc(4);
    const full = Buffer.concat([typeBuf, data]);
    crcBuf.writeUInt32BE(crc32(full), 0);
    return Buffer.concat([len, full, crcBuf]);
  }

  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8;  // bit depth
  ihdrData[9] = 6;  // color type: RGBA
  ihdrData[10] = 0; // compression
  ihdrData[11] = 0; // filter
  ihdrData[12] = 0; // interlace
  const ihdr = makeChunk('IHDR', ihdrData);

  const idat = makeChunk('IDAT', compressed);
  const iend = makeChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdr, idat, iend]);
}

// Canvas-like pixel buffer renderer
class Canvas {
  constructor(size) {
    this.size = size;
    this.data = Buffer.alloc(size * size * 4); // initialized to 0 (transparent)
  }

  setPixel(x, y, r, g, b, a) {
    if (x < 0 || x >= this.size || y < 0 || y >= this.size) return;
    const idx = (Math.floor(y) * this.size + Math.floor(x)) * 4;
    const alpha = a / 255;
    const curA = this.data[idx + 3] / 255;
    const outA = alpha + curA * (1 - alpha);
    if (outA > 0) {
      this.data[idx] = Math.round((r * alpha + this.data[idx] * curA * (1 - alpha)) / outA);
      this.data[idx + 1] = Math.round((g * alpha + this.data[idx + 1] * curA * (1 - alpha)) / outA);
      this.data[idx + 2] = Math.round((b * alpha + this.data[idx + 2] * curA * (1 - alpha)) / outA);
      this.data[idx + 3] = Math.round(outA * 255);
    }
  }

  drawShield(color, borderColor) {
    const s = this.size;
    const cx = s / 2;
    // Shield formula: normalized coordinates [-1, 1]
    for (let y = 0; y < s; y++) {
      const ny = (y / s) * 2 - 1; // -1 at top, +1 at bottom
      for (let x = 0; x < s; x++) {
        const nx = ((x + 0.5) / s) * 2 - 1; // -1 at left, +1 at right
        const absNx = Math.abs(nx);

        // Shield contour
        let inShield = false;
        let inBorder = false;

        // Top edge: ny from -0.85 to 0.75
        if (ny >= -0.85 && ny <= 0.85) {
          // Top arch curve
          const topCurve = -0.85 + (absNx * absNx) * 0.15;
          // Side contour curve tapering down to a point at (0, 0.85)
          let maxWidth = 0.82;
          if (ny > 0.0) {
            maxWidth = 0.82 * Math.cos((ny / 0.85) * (Math.PI / 2));
          }

          if (ny >= topCurve && absNx <= maxWidth) {
            inShield = true;
            // Border detection
            const edgeDist = Math.min(
              maxWidth - absNx,
              ny - topCurve,
              0.85 - ny
            );
            if (edgeDist < (s <= 16 ? 0.22 : 0.12)) {
              inBorder = true;
            }
          }
        }

        if (inShield) {
          if (inBorder) {
            this.setPixel(x, y, borderColor[0], borderColor[1], borderColor[2], 255);
          } else {
            // Slight vertical gradient inside shield
            const factor = 1 - (ny + 0.85) * 0.15;
            const r = Math.min(255, Math.round(color[0] * factor));
            const g = Math.min(255, Math.round(color[1] * factor));
            const b = Math.min(255, Math.round(color[2] * factor));
            this.setPixel(x, y, r, g, b, 255);
          }
        }
      }
    }
  }

  // Draw checkmark inside shield (for Trusted)
  drawCheckmark() {
    const s = this.size;
    const cx = s / 2;
    const cy = s * 0.45;
    const stroke = Math.max(1.5, Math.round(s * 0.12));

    // Points of checkmark: left, bottom, right
    const p1 = [s * 0.30, cy];
    const p2 = [s * 0.45, cy + s * 0.18];
    const p3 = [s * 0.72, cy - s * 0.16];

    this.drawLine(p1[0], p1[1], p2[0], p2[1], [255, 255, 255], stroke);
    this.drawLine(p2[0], p2[1], p3[0], p3[1], [255, 255, 255], stroke);
  }

  // Draw exclamation mark inside shield (for Danger)
  drawExclamation() {
    const s = this.size;
    const cx = s / 2;
    const stroke = Math.max(1.5, Math.round(s * 0.12));
    // Upper bar
    this.drawLine(cx, s * 0.26, cx, s * 0.55, [255, 255, 255], stroke);
    // Dot
    const dotY = s * 0.68;
    const dotR = stroke * 0.55;
    for (let y = Math.floor(dotY - dotR); y <= Math.ceil(dotY + dotR); y++) {
      for (let x = Math.floor(cx - dotR); x <= Math.ceil(cx + dotR); x++) {
        if ((x - cx) ** 2 + (y - dotY) ** 2 <= dotR ** 2) {
          this.setPixel(x, y, 255, 255, 255, 255);
        }
      }
    }
  }

  // Draw question mark inside shield (for Warning / Unknown)
  drawQuestion() {
    const s = this.size;
    const cx = s / 2;
    const stroke = Math.max(1.5, Math.round(s * 0.12));

    // Arc of ?
    for (let a = -Math.PI * 0.7; a <= Math.PI * 0.4; a += 0.1) {
      const r = s * 0.15;
      const qx = cx + r * Math.cos(a);
      const qy = s * 0.35 + r * Math.sin(a);
      this.drawCircle(qx, qy, stroke * 0.5, [255, 255, 255]);
    }
    // Vertical stem of ?
    this.drawLine(cx, s * 0.44, cx, s * 0.55, [255, 255, 255], stroke);
    // Dot of ?
    const dotY = s * 0.68;
    this.drawCircle(cx, dotY, stroke * 0.55, [255, 255, 255]);
  }

  // Draw slash across shield (for Insecure / HTTP)
  drawSlash() {
    const s = this.size;
    const stroke = Math.max(1.5, Math.round(s * 0.12));
    this.drawLine(s * 0.25, s * 0.25, s * 0.75, s * 0.75, [255, 255, 255], stroke);
  }

  drawCircle(cx, cy, r, color) {
    for (let y = Math.floor(cy - r); y <= Math.ceil(cy + r); y++) {
      for (let x = Math.floor(cx - r); x <= Math.ceil(cx + r); x++) {
        if ((x - cx) ** 2 + (y - cy) ** 2 <= r ** 2) {
          this.setPixel(x, y, color[0], color[1], color[2], 255);
        }
      }
    }
  }

  drawLine(x0, y0, x1, y1, color, width) {
    const dx = x1 - x0;
    const dy = y1 - y0;
    const len = Math.hypot(dx, dy);
    if (len === 0) return;
    const steps = Math.ceil(len * 2);
    const r = width / 2;

    for (let i = 0; i <= steps; i++) {
      const t = i / steps;
      const x = x0 + dx * t;
      const y = y0 + dy * t;
      this.drawCircle(x, y, r, color);
    }
  }

  toPNG() {
    return createPNG(this.size, this.size, this.data);
  }
}

// Icon themes
const THEMES = {
  trusted: {
    base: [22, 163, 74],      // #16a34a emerald green
    border: [187, 247, 208],  // #bbf7d0
    draw: c => c.drawCheckmark()
  },
  danger: {
    base: [220, 38, 38],      // #dc2626 bright red
    border: [254, 202, 202],  // #fecaca
    draw: c => c.drawExclamation()
  },
  warning: {
    base: [217, 119, 6],      // #d97706 amber orange
    border: [254, 243, 199],  // #fef3c7
    draw: c => c.drawQuestion()
  },
  insecure: {
    base: [100, 116, 139],    // #64748b slate gray
    border: [226, 232, 240],  // #e2e8f0
    draw: c => c.drawSlash()
  },
  default: {
    base: [37, 99, 235],      // #2563eb royal blue
    border: [191, 219, 254],  // #bfdbfe
    draw: () => {}
  }
};

const SIZES = [16, 32, 48, 128];

for (const [themeName, config] of Object.entries(THEMES)) {
  for (const size of SIZES) {
    const canvas = new Canvas(size);
    canvas.drawShield(config.base, config.border);
    config.draw(canvas);
    const pngBuf = canvas.toPNG();
    const fileName = `icon-${themeName}-${size}.png`;
    fs.writeFileSync(path.join(iconsDir, fileName), pngBuf);
  }
}

// Standard generic aliases from default theme
for (const size of SIZES) {
  const defaultBuf = fs.readFileSync(path.join(iconsDir, `icon-default-${size}.png`));
  fs.writeFileSync(path.join(iconsDir, `icon-${size}.png`), defaultBuf);
}

console.log('Successfully generated all icon sets in icons/');

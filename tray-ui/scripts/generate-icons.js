'use strict';

// Rasteriza os SVGs de assets/logo*.svg em .ico multi-resolução.
// Roda com Node puro (sem Electron — sharp faz a rasterização nativa):
//   node scripts/generate-icons.js

const path = require('node:path');
const fs = require('node:fs');
const sharp = require('sharp');
const toIco = require('to-ico');

const SIZES = [16, 24, 32, 48, 64, 128, 256];
const ASSETS_DIR = path.join(__dirname, '..', 'assets');

const VARIANTS = {
  'tray-idle.ico': 'logo-idle.svg',
  'tray-active.ico': 'logo.svg',
  'tray-block.ico': 'logo-block.svg',
  'app.ico': 'logo.svg',
};

async function main() {
  for (const [outName, svgName] of Object.entries(VARIANTS)) {
    const svgBuffer = fs.readFileSync(path.join(ASSETS_DIR, svgName));
    const pngs = [];
    for (const size of SIZES) {
      const png = await sharp(svgBuffer, { density: 384 })
        .resize(size, size, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
        .png()
        .toBuffer();
      pngs.push(png);
    }
    const icoBuffer = await toIco(pngs);
    fs.writeFileSync(path.join(ASSETS_DIR, outName), icoBuffer);
    console.log(`wrote ${outName} (${SIZES.join(',')})`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

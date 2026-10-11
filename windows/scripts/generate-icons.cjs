// Run: npm install --prefix build/icon-tools @resvg/resvg-js@2.6.2
// Then: node windows/scripts/generate-icons.cjs
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '../..');
const { Resvg } = require(path.join(root, 'build/icon-tools/node_modules/@resvg/resvg-js'));
const svg = fs.readFileSync(path.join(root, 'windows/assets/sb-easy.svg'),'utf8');
const sizes = [16,20,24,32,40,48,64,128,256];
const frames=sizes.map(size=>new Resvg(svg,{fitTo:{mode:'width',value:size}}).render().asPng());
const header=Buffer.alloc(6+16*sizes.length);header.writeUInt16LE(1,2);header.writeUInt16LE(sizes.length,4);
let offset=header.length;
sizes.forEach((size,i)=>{const p=6+i*16;header[p]=size===256?0:size;header[p+1]=header[p];header.writeUInt16LE(1,p+4);header.writeUInt16LE(32,p+6);header.writeUInt32LE(frames[i].length,p+8);header.writeUInt32LE(offset,p+12);offset+=frames[i].length;});
fs.writeFileSync(path.join(root, 'windows/assets/sb-easy.ico'),Buffer.concat([header,...frames]));
fs.writeFileSync(path.join(root, 'build/sb-easy-logo.png'),new Resvg(svg,{fitTo:{mode:'width',value:512}}).render().asPng());

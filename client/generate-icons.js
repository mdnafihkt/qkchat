import sharp from 'sharp';
import fs from 'fs';

const sizes = [72, 96, 128, 144, 152, 192, 384, 512];
const input = 'public/qkchat.png';
const outDir = 'public/icons';

if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
}

async function generateIcons() {
    console.log('Generating icons...');
    for (const size of sizes) {
        await sharp(input)
            .resize(size, size)
            .webp()
            .toFile(`${outDir}/icon-${size}.webp`);
        console.log(`Created icon-${size}.webp`);
    }
    console.log('Done!');
}

generateIcons().catch(console.error);

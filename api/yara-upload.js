import { put } from '@vercel/blob';
import { unzipSync } from 'fflate';

export const config = { api: { bodyParser: false }, maxDuration: 60 };

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const supplied = String(req.headers.authorization || '').replace(/^Bearer\\s+/i, '');
  const expected = process.env.YARA_TEMP_UPLOAD_KEY || '';
  if (!expected || supplied.length !== expected.length || !Buffer.from(supplied).equals(Buffer.from(expected))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 8 * 1024 * 1024) return res.status(413).json({ error: 'ZIP exceeds 8 MB limit' });
      chunks.push(chunk);
    }
    const archive = Buffer.concat(chunks);
    if (!archive.length) return res.status(400).json({ error: 'No ZIP file received' });
    const entries = unzipSync(new Uint8Array(archive));
    const images = Object.entries(entries).filter(([name, bytes]) =>
      /^[0-9]{13}\\.jpg$/i.test(name) && bytes.length > 4 &&
      bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff
    );
    if (images.length !== 41) return res.status(400).json({ error: 'Expected 41 original JPEG images; found ' + images.length });
    const totalBytes = images.reduce((n, [, b]) => n + b.length, 0);
    if (totalBytes > 12 * 1024 * 1024) return res.status(413).json({ error: 'Uncompressed images exceed limit' });

    const uploaded = [];
    for (let i = 0; i < images.length; i += 5) {
      const batch = await Promise.all(images.slice(i, i + 5).map(async ([name, bytes]) => {
        const blob = await put('yara-products/' + name, Buffer.from(bytes), {
          access: 'public', addRandomSuffix: false, contentType: 'image/jpeg',
          token: process.env.BLOB_READ_WRITE_TOKEN
        });
        return { name, url: blob.url, size: bytes.length };
      }));
      uploaded.push(...batch);
    }
    return res.status(200).json({ uploaded: uploaded.length, totalBytes, files: uploaded });
  } catch (error) {
    console.error('YARA ZIP upload failed:', error);
    return res.status(500).json({ error: 'Could not process the ZIP upload' });
  }
}

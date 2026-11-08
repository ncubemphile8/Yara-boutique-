import { put } from '@vercel/blob';

export const config = { api: { bodyParser: false }, maxDuration: 60 };

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const supplied = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const expected = process.env.YARA_TEMP_UPLOAD_KEY || '';
  if (!expected || supplied.length !== expected.length || !Buffer.from(supplied).equals(Buffer.from(expected))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const filename = String(req.query.filename || '');
  if (!/^[0-9]{13}\.jpg$/i.test(filename)) return res.status(400).json({ error: 'Invalid filename' });

  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 2 * 1024 * 1024) return res.status(413).json({ error: 'Image exceeds 2 MB limit' });
      chunks.push(chunk);
    }
    if (!size) return res.status(400).json({ error: 'Empty upload' });

    const blob = await put('yara-products/' + filename, Buffer.concat(chunks), {
      access: 'public',
      addRandomSuffix: false,
      contentType: 'image/jpeg',
      token: process.env.BLOB_READ_WRITE_TOKEN
    });
    return res.status(200).json({ url: blob.url, pathname: blob.pathname, size });
  } catch (error) {
    console.error('YARA upload failed:', error);
    return res.status(500).json({ error: 'Upload failed' });
  }
}

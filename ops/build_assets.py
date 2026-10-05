"""Build compressed public assets on the server from its GitHub checkout."""
import gzip
import re
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
# Derivatives are built on Oracle. Original images remain intact in GitHub.
for path in (ROOT / 'images' / 'thumbnails').glob('*.png'):
    with Image.open(path) as image:
        image.thumbnail((384, 512), Image.Resampling.LANCZOS)
        image.convert('RGB').save(path.with_suffix('.webp'), quality=78, method=6)
revision = (ROOT / 'REVISION').read_text().strip() if (ROOT / 'REVISION').exists() else None
if revision:
    for css in (ROOT / 'css').rglob('*.css'):
        text = css.read_text(encoding='utf-8')
        text = re.sub(r'url\(([\"\']?)/(fonts|images)/', lambda m: 'url(' + m[1] + '/assets/' + revision + '/' + m[2] + '/', text)
        css.write_text(text, encoding='utf-8')
for directory in ('js', 'css', 'images', 'fonts'):
    for path in (ROOT / directory).rglob('*'):
        if path.is_file() and path.suffix in ('.js', '.css', '.svg', '.ttf', '.json'):
            raw = path.read_bytes()
            compressed = gzip.compress(raw, compresslevel=9, mtime=0)
            if len(compressed) < len(raw):
                path.with_name(path.name + '.gz').write_bytes(compressed)
print('Precompressed public assets built from the GitHub release.')

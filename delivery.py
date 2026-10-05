"""Versioned public assets and a signed, asynchronous GitHub deploy signal."""
import hashlib
import hmac
import os
import re
from pathlib import Path
from flask import abort, jsonify, request, send_from_directory

PUBLIC = ('js', 'css', 'images', 'fonts', 'audio', 'videos')


def init_delivery(app, root):
    version = os.environ.get('RELEASE_SHA', 'development')
    app.config.setdefault('GITHUB_WEBHOOK_SECRET', os.environ.get('GITHUB_WEBHOOK_SECRET', ''))
    app.config.setdefault('DEPLOY_SIGNAL', '/var/lib/cubetastic/deploy-request')
    def asset(path):
        path = path.lstrip('/')
        if path.startswith('images/thumbnails/') and (root / path).with_suffix('.webp').is_file():
            path = str(Path(path).with_suffix('.webp')).replace('\\', '/')
        return f'/assets/{version}/{path}'
    app.jinja_env.globals['asset'] = asset

    @app.get('/assets/<revision>/<directory>/<path:filename>')
    def versioned_asset(revision, directory, filename):
        if directory not in PUBLIC or revision != version:
            abort(404)
        response = send_from_directory(root / directory, filename)
        response.headers['Cache-Control'] = ('public, max-age=31536000, immutable'
            if re.fullmatch('[a-f0-9]{40}', version) else 'no-cache')
        return response

    @app.get('/sw.js')
    def service_worker():
        source = (root / 'static' / 'sw.js').read_text(encoding='utf-8').replace('__VERSION__', version)
        return app.response_class(source, mimetype='application/javascript', headers={'Cache-Control': 'no-cache'})

    @app.post('/hooks/github')
    def github_push():
        secret = app.config['GITHUB_WEBHOOK_SECRET']
        if not secret:
            abort(503)
        expected = 'sha256=' + hmac.new(secret.encode(), request.get_data(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, request.headers.get('X-Hub-Signature-256', '')):
            abort(403)
        event = request.headers.get('X-GitHub-Event')
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            abort(400)
        if event == 'ping':
            return jsonify(ok=True)
        repo = data.get('repository') or {}
        if event != 'push' or repo.get('full_name') != 'ash-gram/cubetastic' or data.get('ref') != 'refs/heads/main' or data.get('deleted'):
            return jsonify(ignored=True)
        # No shell, user-supplied paths, or builds in the request process.
        # systemd.path activates the root-owned deploy service, which pulls GitHub.
        Path(app.config['DEPLOY_SIGNAL']).touch(mode=0o600)
        return jsonify(queued=True), 202

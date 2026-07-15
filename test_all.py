"""
端到端测试 - 拾贝平台文字/图片模块所有 API
"""
import urllib.request, urllib.error, urllib.parse
import json, struct, zlib, os, sys, time, http.cookiejar

BASE = 'http://127.0.0.1:5000'
passed = 0
failed = 0
results = []

def test(name, ok, detail=''):
    global passed, failed
    if ok:
        passed += 1
        print(f'  [PASS] {name}')
    else:
        failed += 1
        print(f'  [FAIL] {name}  -- {detail}')

# Setup cookie jar
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
urllib.request.install_opener(opener)

# Login
print("=== Login ===")
login_data = urllib.parse.urlencode({'username': 'admin', 'password': 'admin123'}).encode()
req = urllib.request.Request(BASE + '/login', data=login_data)
resp = urllib.request.urlopen(req)
print(f"Login status: {resp.status}")

def api(method, path, data=None, raw_data=None, is_json=True):
    url = BASE + path
    if data is not None:
        req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'),
            headers={'Content-Type': 'application/json'}, method=method)
    elif raw_data is not None:
        req = urllib.request.Request(url, data=raw_data, method=method)
    else:
        req = urllib.request.Request(url, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=20)
        body = resp.read()
        if is_json:
            try:
                return resp.status, json.loads(body)
            except:
                return resp.status, body
        return resp.status, body
    except urllib.error.HTTPError as e:
        err_body = e.read()
        try:
            return e.code, json.loads(err_body)
        except:
            return e.code, {'error': str(e), 'body': err_body[:200]}
    except Exception as e:
        return 0, {'error': str(e)}

def make_png(w=10, h=10):
    """Create a valid minimal PNG file"""
    def chunk(ctype, data):
        c = ctype + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
    raw = b''
    for y in range(h):
        raw += b'\x00'  # filter: none
        for x in range(w):
            raw += bytes([(x + y * 2) * 7 % 256] * 3)  # RGB
    ihdr = struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')

# ============================
#  TEXT MODULE
# ============================
print("\n=== TEXT MODULE ===")

# 1. Upload file
print("\n-- Upload --")
boundary = '----TestBoundary987'
body = b''
body += b'--' + boundary.encode() + b'\r\n'
body += b'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
body += b'Content-Type: text/plain\r\n\r\n'
body += b'Hello World\nThis is a test file.\nIt has multiple lines.\nPython is great for automation.\nThe quick brown fox jumps.\nEnd of file.\n'
body += b'\r\n--' + boundary.encode() + b'--\r\n'

# 必须传 Content-Type 头，Flask 才能解析 multipart
req = urllib.request.Request(BASE + '/api/text/upload', data=body,
    headers={'Content-Type': 'multipart/form-data; boundary=' + boundary})
resp = urllib.request.urlopen(req)
d = json.loads(resp.read())
test("Upload .txt file", d.get('ok') == True, str(d))
text_uid = d.get('uid', '')
print(f"  uid = {text_uid}")

# 2. Paste text
print("\n-- Paste --")
code, d = api('POST', '/api/text/paste', data={
    'title': 'Paste Test Document',
    'content': 'This is pasted content. It mentions Python several times. Python developers love Flask and Python is versatile.'
})
test("Paste text content", d.get('ok') == True, str(d))
paste_uid = d.get('uid', '')
print(f"  uid = {paste_uid}")

# 3. Fetch web page
print("\n-- Fetch --")
code, d = api('POST', '/api/text/fetch', data={'url': 'https://example.com'})
if not d.get('ok'):
    code, d = api('POST', '/api/text/fetch', data={'url': 'https://httpbin.org/html'})
fetch_ok = d.get('ok') == True
test("Fetch web page text", fetch_ok, f"msg={d.get('msg','')}, lines={d.get('lines','')}")
fetch_uid = d.get('uid', '')

# 4. List texts
print("\n-- List --")
code, d = api('GET', '/api/text/list')
test("List stored texts", d.get('ok') and len(d.get('items', [])) >= 1,
     f"items={len(d.get('items', []))}")

# 5. View text
print("\n-- View --")
if text_uid:
    code, d = api('GET', '/api/text/view/' + text_uid)
    test("View text content", d.get('ok') and len(d.get('content', '')) > 0,
         f"content_len={len(d.get('content',''))}")

# 6. Search text
print("\n-- Search --")
if text_uid:
    code, d = api('GET', '/api/text/search/' + text_uid + '?q=Python')
    test("Search keyword (basic)", d.get('ok') and d.get('count', 0) > 0,
         f"count={d.get('count')}, has_highlight={'<mark' in d.get('html','')}")

    code, d = api('GET', '/api/text/search/' + text_uid + '?q=Python&whole_word=1')
    test("Search (whole word on)", d.get('ok') == True, f"count={d.get('count',0)}")

    code, d = api('GET', '/api/text/search/' + text_uid + '?q=test&smart_punct=1')
    test("Search (smart punct on)", d.get('ok') == True, f"count={d.get('count',0)}")

    # Test smart punct: search for "it's" style
    code, d = api('GET', '/api/text/search/' + text_uid + '?q=great&smart_punct=1')
    test("Search 'great'", d.get('ok') == True, f"count={d.get('count',0)}")

# 7. Delete text
print("\n-- Delete --")
if paste_uid:
    code, d = api('POST', '/api/text/delete/' + paste_uid)
    test("Delete text", d.get('ok') == True, str(d))

# ============================
#  IMAGE MODULE
# ============================
print("\n=== IMAGE MODULE ===")

# 1. Upload image
print("\n-- Upload --")
png = make_png(100, 60)
boundary = '----ImgBoundary123'
body = b''
body += b'--' + boundary.encode() + b'\r\n'
body += b'Content-Disposition: form-data; name="file"; filename="test_image.png"\r\n'
body += b'Content-Type: image/png\r\n\r\n'
body += png + b'\r\n'
body += b'--' + boundary.encode() + b'--\r\n'

req = urllib.request.Request(BASE + '/api/image/upload', data=body,
    headers={'Content-Type': 'multipart/form-data; boundary=' + boundary})
resp = urllib.request.urlopen(req)
d = json.loads(resp.read())
test("Upload image", d.get('ok') == True, str(d))
img_uid = d.get('uid', '')
print(f"  uid = {img_uid}")

# 2. Fetch images from URL
print("\n-- Fetch --")
code, d = api('POST', '/api/image/fetch', data={'url': 'https://www.example.com'})
# This just tests the endpoint works (even if no images found on example.com)
test("Fetch images from URL", 'ok' in d, f"msg={d.get('msg','?')}, images={len(d.get('images',[]))}")

# 3. Image save-url
print("\n-- Save URL --")
# Use a reliable image source (httpbin.org is flaky)
code, d = api('POST', '/api/image/save-url', data={'url': 'https://placehold.co/200x150.png'})
save_ok = d.get('ok') in [True, False]  # endpoint must respond
test("Save image from URL", d.get('ok') == True,
     f"ok={d.get('ok')}, msg={d.get('msg','')[:80]}")
save_uid = d.get('uid', '')

# 4. Image list
print("\n-- Gallery List --")
code, d = api('GET', '/api/image/list')
test("List images", d.get('ok') and len(d.get('items', [])) >= 1,
     f"items={len(d.get('items', []))}")

# 5. Image view (raw binary)
print("\n-- View --")
if img_uid:
    code, body = api('GET', '/api/image/view/' + img_uid, is_json=False)
    is_image = isinstance(body, bytes) and len(body) > 50
    test("View image (raw bytes)", is_image, f"size={len(body) if isinstance(body, bytes) else '?'}")

# 6. Image proxy /img
print("\n-- Proxy --")
# The /img proxy fetches from remote and caches locally
code, body = api('GET', '/img?url=' + urllib.parse.quote('https://placehold.co/50x50.png'), is_json=False)
proxy_ok = isinstance(body, bytes) and len(body) > 50
test("Image proxy /img", proxy_ok,
     f"size={len(body) if isinstance(body, bytes) else str(body)[:80]}")

# 7. Tags
print("\n-- Tags --")
if img_uid:
    code, d = api('POST', '/api/image/tags/' + img_uid, data={'tags': ['nature', 'test', 'landscape']})
    test("Set image tags", d.get('ok') and d.get('tags') == ['nature', 'test', 'landscape'], str(d))

    code, d = api('GET', '/api/image/tags/' + img_uid)
    test("Get image tags", d.get('ok') and len(d.get('tags', [])) == 3,
         f"tags={d.get('tags')}")

# 8. All tags
print("\n-- All Tags --")
code, d = api('GET', '/api/image/tags')
test("Get all tags cloud", d.get('ok') and len(d.get('tags', [])) >= 1,
     f"tag_count={len(d.get('tags',[]))}")

# 9. Delete single tag from image
print("\n-- Delete Tag --")
if img_uid:
    code, d = api('DELETE', '/api/image/tags/' + img_uid + '/landscape')
    test("Remove single tag from image", d.get('ok') == True, str(d))

    code, d = api('GET', '/api/image/tags/' + img_uid)
    test("Verify tag removed", d.get('ok') and 'landscape' not in d.get('tags', []),
         f"tags={d.get('tags')}")

# 10. Stats
print("\n-- Stats --")
code, d = api('GET', '/api/image/stats')
test("Image stats", d.get('ok') and d.get('total_count', 0) > 0,
     f"count={d.get('total_count')}, size_mb={d.get('total_size_mb')}")
test("Stats has ext breakdown", 'ext_count' in d, str(d.get('ext_count', {})))

# 11. Baidu image search
print("\n-- Search Engine --")
code, d = api('POST', '/api/image/search', data={'keyword': 'sunset', 'page': 0})
test("Baidu image search", d.get('ok') in [True, False], f"{d.get('ok')}, msg={d.get('msg','?')[:60]}")

# 12. Batch download zip
print("\n-- Zip Download --")
if img_uid:
    code, body = api('POST', '/api/image/download-zip', data={'uids': [img_uid]}, is_json=False)
    is_zip = isinstance(body, bytes) and len(body) > 100
    test("Batch download as zip", is_zip, f"size={len(body) if isinstance(body, bytes) else '?'}")

# 13. Global tag delete
print("\n-- Global Tag Delete --")
code, d = api('DELETE', '/api/image/tag/nature')
test("Global delete tag 'nature'", d.get('ok') == True, f"removed_from={d.get('removed_from')}")

# 14. Delete image
print("\n-- Delete Image --")
if save_uid:
    code, d = api('POST', '/api/image/delete/' + save_uid)
    test("Delete image", d.get('ok') == True, str(d))

# Final cleanup
if text_uid:
    api('POST', '/api/text/delete/' + text_uid)
if fetch_uid:
    api('POST', '/api/text/delete/' + fetch_uid)

# ============================
#  SUMMARY
# ============================
print("\n" + "=" * 50)
print(f"  RESULTS: {passed} passed, {failed} failed, {passed + failed} total")
print("=" * 50)

if failed > 0:
    sys.exit(1)
else:
    print("All tests passed!")

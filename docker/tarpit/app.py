import asyncio
import random
import time
from aiohttp import web

# ==============================================================================
# Tarpit Server (حفرة القطران) - Malicious Active Defense
#
# This server intentionally hangs connections to break automated scanners
# (like Nmap, Nikto, DirBuster, Burp Suite) and exhausts the attacker's resources.
# ==============================================================================

async def tarpit_handler(request):
    """
    Tarpit logic: 
    Instead of returning a 404 or 200, we accept the connection 
    and send back 1 random byte every 10-20 seconds... forever.
    """
    attacker_ip = request.remote
    print(f"[!] Tarpit engaged: Trapped scanner from {attacker_ip} on path {request.path}")
    
    response = web.StreamResponse()
    response.headers['Content-Type'] = 'text/html'
    response.headers['Server'] = 'Apache/2.4.41 (Ubuntu)' # Fake header
    
    # We send a 200 OK so the scanner thinks it found a real page and waits for it.
    response.set_status(200)
    await response.prepare(request)

    # Poison Payload (SQLi payload injected back to the scanner's potential database)
    poison = b"<!-- ' OR 1=1; DROP TABLE logs; -- >\n"
    await response.write(poison)

    try:
        while True:
            # Send a random hex byte very slowly
            junk = hex(random.randint(0, 255)).encode() + b"\n"
            await response.write(junk)
            # Sleep for 10 to 20 seconds
            await asyncio.sleep(random.randint(10, 20))
    except Exception:
        print(f"[+] Attacker {attacker_ip} finally gave up and closed the connection.")
    
    return response

app = web.Application()
# Catch all routes
app.router.add_route('*', '/{tail:.*}', tarpit_handler)

if __name__ == '__main__':
    print("🔥 Starting Khandaq Tarpit (Port 80)...")
    web.run_app(app, host='0.0.0.0', port=80)

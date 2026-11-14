import asyncio
import os
import time
from playwright.async_api import async_playwright

DOWNLOAD_DIR = r"C:\Users\atpad\AgentBlackBox\assets\notebooklm"

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp('http://127.0.0.1:9222')
        context = browser.contexts[0]
        page = [pg for pg in context.pages if 'notebook/' in pg.url][0]
        
        # Configure CDP download
        client = await context.new_cdp_session(page)
        await client.send('Page.setDownloadBehavior', {
            'behavior': 'allow',
            'downloadPath': DOWNLOAD_DIR
        })
        
        print("Waiting for video to finish applying finishing touches...", flush=True)
        start = time.time()
        while time.time() - start < 300: # 5 min max
            status = await page.evaluate("""() => {
                const s = document.querySelector('section.studio-panel');
                if (!s) return {done: false, text: ''};
                const text = s.innerText;
                const gen = text.includes('Generating Cinematic Video Overview') || text.includes('Generating Video Overview');
                return {
                    gen,
                    text: text.slice(-250).replace(/\\n/g, ' | ')
                };
            }""")
            
            elapsed = int(time.time() - start)
            print(f"[{elapsed}s] Video gen: {status['gen']} | {status['text']}", flush=True)
            
            if not status['gen']:
                print("🎉 VIDEO FINISHED GENERATING! Downloading...", flush=True)
                await page.wait_for_timeout(2000)
                await page.screenshot(path=os.path.join(DOWNLOAD_DIR, 'video_done_screen.png'))
                
                # Find the more_vert buttons in studio
                buttons = await page.evaluate("""() => {
                    const studio = document.querySelector('section.studio-panel');
                    const btns = [];
                    studio.querySelectorAll('button').forEach(b => {
                        const aria = b.getAttribute('aria-label') || '';
                        const text = b.innerText || '';
                        if (aria === 'More' || text.includes('more_vert')) {
                            const r = b.getBoundingClientRect();
                            btns.push({x: r.x + r.width/2, y: r.y + r.height/2});
                        }
                    });
                    return btns;
                }""")
                print("Found more_vert buttons:", buttons, flush=True)
                if buttons:
                    # Video card is usually at the top or bottom of artifact list
                    # Let's click the first one (or inspect which one is video)
                    for i, b in enumerate(buttons):
                        print(f"Clicking more_vert button {i} at ({b['x']}, {b['y']})...", flush=True)
                        await page.mouse.click(b['x'], b['y'])
                        await page.wait_for_timeout(1000)
                        
                        dl = page.locator('button:has-text("Download"), div[role="menuitem"]:has-text("Download")')
                        if await dl.count() > 0:
                            print(f"Found Download on button {i}! Clicking...", flush=True)
                            await dl.first.click()
                            await page.wait_for_timeout(5000)
                            print("Download initiated!", flush=True)
                            return
                        else:
                            await page.keyboard.press("Escape")
                            await page.wait_for_timeout(500)
                break
                
            await asyncio.sleep(10)

asyncio.run(main())

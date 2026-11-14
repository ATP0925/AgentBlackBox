import asyncio
import os
import time
import shutil
from playwright.async_api import async_playwright

DOWNLOAD_DIR = r"C:\Users\atpad\AgentBlackBox\assets\notebooklm"
BRAIN_DIR = r"C:\Users\atpad\.gemini\antigravity\brain\c18141ab-92a9-4d88-9f75-8c9682ab9957"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

async def run_downloader():
    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp('http://127.0.0.1:9222')
        context = browser.contexts[0]
        pages = [pg for pg in context.pages if 'notebook/' in pg.url]
        if not pages:
            print("No notebook page found!", flush=True)
            return
        page = pages[0]
        
        # Set download directory
        client = await context.new_cdp_session(page)
        await client.send('Page.setDownloadBehavior', {
            'behavior': 'allow',
            'downloadPath': DOWNLOAD_DIR
        })
        print(f"[*] CDP Download folder configured to: {DOWNLOAD_DIR}", flush=True)
        
        start_time = time.time()
        video_downloaded = False
        audio_downloaded = False
        
        while time.time() - start_time < 900: # 15 minutes max
            studio_status = await page.evaluate("""() => {
                const s = document.querySelector('section.studio-panel');
                if (!s) return {text: ''};
                const text = s.innerText;
                const audio_gen = text.includes('Generating Audio Overview');
                const video_gen = text.includes('Generating Cinematic Video Overview') || text.includes('Generating Video Overview');
                return {
                    text: text.slice(-250).replace(/\\n/g, ' | '),
                    audio_gen,
                    video_gen
                };
            }""")
            
            elapsed = int(time.time() - start_time)
            print(f"[{elapsed}s] Video: {'GEN' if studio_status['video_gen'] else 'DONE'}, Audio: {'GEN' if studio_status['audio_gen'] else 'DONE'}", flush=True)
            print(f"     Status: {studio_status['text']}", flush=True)
            
            # Check if Audio is done
            if not studio_status['audio_gen'] and not audio_downloaded:
                print(">>> Audio Overview completed! Attempting download...", flush=True)
                # Look for more_vert or download button for audio
                downloaded = await download_artifact(page, "audio")
                if downloaded:
                    audio_downloaded = True
                    print("✅ Audio Overview download initiated!", flush=True)

            # Check if Video is done
            if not studio_status['video_gen'] and not video_downloaded:
                print(">>> Video Overview completed! Attempting download...", flush=True)
                downloaded = await download_artifact(page, "video")
                if downloaded:
                    video_downloaded = True
                    print("✅ Video Overview download initiated!", flush=True)

            if video_downloaded and audio_downloaded:
                print("🎉 BOTH VIDEO AND AUDIO DOWNLOADED SUCCESSFULLY!", flush=True)
                break
                
            await asyncio.sleep(15)

async def download_artifact(page, kind):
    try:
        # Find all cards or more_vert buttons in studio panel
        elements = await page.evaluate("""(kind) => {
            const studio = document.querySelector('section.studio-panel');
            if (!studio) return [];
            const results = [];
            studio.querySelectorAll('div, button').forEach(el => {
                const aria = el.getAttribute('aria-label') || '';
                const text = el.innerText || '';
                if (aria.includes('More') || aria.includes('options') || text.includes('more_vert')) {
                    const rect = el.getBoundingClientRect();
                    results.push({tag: el.tagName, aria, rect: {x: rect.x, y: rect.y, w: rect.width, h: rect.height}});
                }
            });
            return results;
        }""", kind)
        
        print(f"Found {len(elements)} option buttons in studio:", elements, flush=True)
        if elements:
            # Click the last more_vert button (most recent artifact)
            target = elements[-1]
            x = target['rect']['x'] + target['rect']['w'] / 2
            y = target['rect']['y'] + target['rect']['h'] / 2
            await page.mouse.click(x, y)
            await page.wait_for_timeout(1000)
            
            # Look for Download in menu
            dl_btn = page.locator('button:has-text("Download"), div[role="menuitem"]:has-text("Download")').first
            if await dl_btn.count() > 0:
                await dl_btn.click()
                print("Clicked Download menuitem!", flush=True)
                await page.wait_for_timeout(3000)
                return True
            else:
                print("Download menuitem not visible yet; dismiss menu", flush=True)
                await page.keyboard.press("Escape")
        return False
    except Exception as e:
        print(f"Download attempt error: {e}", flush=True)
        return False

if __name__ == '__main__':
    asyncio.run(run_downloader())

import asyncio
import httpx

async def test():
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        try:
            r = await c.post('https://172.23.31.180/web_api/login', json={'user':'admin','password':''})
            print(r.status_code, r.text)
        except Exception as e:
            print(repr(e))

asyncio.run(test())

import os
import json
import logging
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse
import httpx
import redis.from_url as redis_from_url  # Đảm bảo dùng chung Redis kết nối với Wispbyte

app = FastAPI(title="Equinox V2 - OAuth2 Serverless Proxy")

# Cấu hình Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("EquinoxOAuth2")

# Tải cấu hình từ Biến môi trường (Environment Variables)
REDIS_URI = os.getenv("REDIS_URI")
OAUTH2_REDIRECT_URI = os.getenv("OAUTH2_REDIRECT_URI")

# Định danh 2 Bot đối lập
BOT_CONFIGS = {
    "luminous": {
        "client_id": os.getenv("LUMINOUS_CLIENT_ID"),
        "client_secret": os.getenv("LUMINOUS_CLIENT_SECRET"),
    },
    "tenebris": {
        "client_id": os.getenv("TENEBRIS_CLIENT_ID"),
        "client_secret": os.getenv("TENEBRIS_CLIENT_SECRET"),
    }
}

# Kết nối Redis tập trung
try:
    redis_client = redis_from_url(REDIS_URI, decode_responses=True)
except Exception as e:
    logger.error(f"Không thể kết nối đến Redis: {e}")
    redis_client = None

@app.get("/")
def read_root():
    return {"status": "online", "message": "Equinox Network V2 - OAuth2 Proxy Service"}

@app.get("/login/{bot_type}")
def login(bot_type: str, user_id: str):
    """
    Tạo link chuyển hướng người dùng đến trang xác thực OAuth2 của Discord
    """
    bot = bot_type.lower()
    if bot not in BOT_CONFIGS or not BOT_CONFIGS[bot]["client_id"]:
        raise HTTPException(status_code=400, detail="Cấu hình Identity Bot không hợp lệ hoặc thiếu.")
        
    client_id = BOT_CONFIGS[bot]["client_id"]
    # Scope cần thiết để chỉnh sửa Rich Presence / Profile Customization
    scope = "identify connections activities.write" 
    
    # Mã hóa trạng thái state (bao gồm bot_type và user_id) để nhận diện khi callback
    state = json.dumps({"bot": bot, "user_id": user_id})
    
    discord_url = (
        f"https://discord.com/api/oauth2/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri={httpx.URL(OAUTH2_REDIRECT_URI)}"
        f"&response_type=code"
        f"&scope={scope}"
        f"&state={state}"
    )
    return RedirectResponse(url=discord_url)

@app.get("/callback")
async def callback(code: str, state: str):
    """
    Nơi Discord trả code về, tiến hành trao đổi token và lưu vào Redis
    """
    if not redis_client:
        raise HTTPException(status_code=500, detail="Lỗi kết nối cơ sở dữ liệu Redis.")
        
    try:
        state_data = json.loads(state)
        bot = state_data.get("bot")
        user_id = state_data.get("user_id")
    except Exception:
        raise HTTPException(status_code=400, detail="Dữ liệu Trạng thái (State) không hợp lệ.")

    if bot not in BOT_CONFIGS:
        raise HTTPException(status_code=400, detail="Mã định danh Bot không tồn tại.")

    config = BOT_CONFIGS[bot]
    
    # Gửi yêu cầu đổi Code lấy Access Token từ Discord API
    async with httpx.AsyncClient() as client:
        data = {
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": OAUTH2_REDIRECT_URI,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        response = await client.post("https://discord.com/api/oauth2/token", data=data, headers=headers)
        
        if response.status_code != 200:
            logger.error(f"Lỗi trao đổi token: {response.text}")
            return JSONResponse(status_code=400, content={"error": "Thất bại khi xác thực với Discord."})
            
        token_data = response.json()
        
        # Lưu trữ Access Token & Refresh Token vào Redis trung tâm để Bot ở Wispbyte lấy ra xài
        redis_key = f"equinox:oauth2:{bot}:{user_id}"
        redis_client.set(redis_key, json.dumps(token_data), ex=token_data.get("expires_in", 604800))
        
        # Thông báo thành công đồng bộ hóa tài khoản cho hệ thống
        redis_client.publish(f"equinox:events:{bot}", json.dumps({"event": "oauth_success", "user_id": user_id}))

    # Trả về giao diện HTML thông báo thành công cho người dùng đóng tab
    html_content = """
    <html>
        <head><title>Xác thực thành công</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; background-color: #1a1a2e; color: #ffffff; padding-top: 50px;">
            <h1 style="color: #4ecca3;">Equinox Network V2</h1>
            <p>Liên kết tài khoản thành công! Bạn có thể đóng tab này và quay lại Discord.</p>
        </body>
    </html>
    """
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html_content, status_code=200)

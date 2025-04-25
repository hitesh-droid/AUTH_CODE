from fastapi import FastAPI, Request, Form, status, Depends
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from werkzeug.security import check_password_hash
from pymongo import MongoClient
import uuid
import certifi
import pyotp


class SessionManager:
    def __init__(self, mongo_uri: str, database_name: str):
        self.client = MongoClient(mongo_uri, tls=True, tlsCAFile=certifi.where())
        self.db = self.client[database_name]

    @staticmethod
    def verify_password(plain_password, hashed_password):
        return check_password_hash(hashed_password, plain_password)

    def create_session(self, email: str):
        session_id = str(uuid.uuid4())
        self.db.sessions.insert_one({"session_id": session_id, "email": email})
        return session_id

    def delete_session(self, session_id: str):
        self.db.sessions.delete_one({"session_id": session_id})

    def get_session(self, session_id: str):
        return self.db.sessions.find_one({"session_id": session_id})


def create_auth_app(mongo_uri: str, database_name: str) -> FastAPI:
    app = FastAPI()
    templates = Jinja2Templates(directory="login_module/templates")

    # Mount the static files directory
    app.mount("/static", StaticFiles(directory="login_module/static"), name="static")

    session_manager = SessionManager(mongo_uri, database_name)

    @app.get("/login")
    async def login_page(request: Request):
        session_id = request.cookies.get("session_id")
        session = session_manager.get_session(session_id)

        if session:
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

        return templates.TemplateResponse("login_page.html", {"request": request})

    @app.post("/login")
    async def login(request: Request, email: str = Form(...), password: str = Form(...)):
        session_id = request.cookies.get("session_id")
        session = session_manager.get_session(session_id)
        if session:
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

        try:
            user = session_manager.db.users.find_one({"email": email.lower()})
            if user and session_manager.verify_password(password, user["password"]):
                session_id = session_manager.create_session(email)
                response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
                response.set_cookie(key="session_id", value=session_id)
                return response
            else:
                error_message = "Invalid email or password"
        except Exception as e:
            error_message = "An error occurred. Please try again."

        return templates.TemplateResponse("login_page.html", {"request": request, "error": error_message})

    @app.get("/logout")
    async def logout(request: Request):
        session_id = request.cookies.get("session_id")
        if session_id:
            session_manager.delete_session(session_id)
        response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        response.delete_cookie("session_id")
        return response

    @app.get("/dashboard")
    async def dashboard(request: Request, search_query: str = ""):
        session_id = request.cookies.get("session_id")
        session = session_manager.get_session(session_id)
        if not session:
            return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

        # Fetch all users from the database
        users = session_manager.db.UserAuthData.find({}, {"_id": 0, "ID": 1, "email": 1, "OTP_Secret": 1})
        if search_query:
            # Apply the search filter (case-insensitive search by email)
            users = filter(lambda user: search_query.lower() in user['email'].lower(), users)

        # Generate OTPs for each user
        user_otps = []
        for user in users:
            if "OTP_Secret" in user:
                totp = pyotp.TOTP(user["OTP_Secret"]).now()  # OTP generated using OTP secret from DB
                user_otps.append({
                    "email": user["ID"],
                    "otp": totp
                })

        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "users": user_otps,
            "search_query": search_query  # Send the search query to preserve it in the input
        })

    @app.get("/api/totp")
    async def fetch_totp():
        users = session_manager.db.UserAuthData.find({}, {"_id": 0, "ID": 1, "OTP_Secret": 1})
        data = []

        for user in users:
            if "OTP_Secret" in user:
                totp = pyotp.TOTP(user["OTP_Secret"]).now()
                data.append({
                    "email": user["email"],
                    "totp": totp
                })

        data.sort(key=lambda x: x['email'].lower())
        return JSONResponse(content={"data": data})

    @app.get("/")
    async def root_redirect(request: Request):
        session_id = request.cookies.get("session_id")
        session = session_manager.get_session(session_id)
        if session:
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    @app.get("/api/get_totps")
    async def get_totps():
        users = session_manager.db.UserAuthData.find({}, {"_id": 0, "ID": 1, "OTP_Secret": 1})
        data = []

        for user in users:
            # Generate OTP for each user
            totp = pyotp.TOTP(user["OTP_Secret"]).now()
            data.append({
                "email": user["ID"].split('@')[0],
                "otp": totp
            })

        return JSONResponse(content={"users": data})

    return app

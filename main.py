import os

from login_module.loginauth import *
MONGO_URI = os.environ.get("MONGO_URI")
DB = os.environ.get("DB")


# Create the FastAPI app using the authentication module
app = create_auth_app(MONGO_URI, DB)

from flask import (
    Flask,
    request,
    jsonify,
    redirect,
    url_for,
    send_from_directory,
    jsonify,
    send_file,
    render_template,
    make_response,
)
from flask_cors import CORS
import json
import random
import bcrypt
import base64
from PIL import Image
import io

# pythonanywherePath = "/home/helli3olympic/mysite/"
# pythonanywherePath = "d:/temp/JozveSara-Backend/"
pythonanywherePath = "./"

app = Flask(__name__)
CORS(app, expose_headers=["Content-Disposition"])
apiKey = "167qw3er13rdfwdxcaaeqwf23frq3ewfrt34gt243edqwjy5634!@#$@$TFGEDS!#@R738289qw23r234rf07940936"


def hash_password(password):
    # Generate a salt
    salt = bcrypt.gensalt()

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)

    # Return the hashed password as a string
    return hashed_password.decode("utf-8")


def verify_password(password, hashed_password):
    # Verify the password
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))


@app.route("/")
def page_main():
    dataFile = open(f"{pythonanywherePath}data.json").read()
    dataJson = json.loads(dataFile)
    return render_template("index.html", data=dataJson)


@app.route("/signin", methods=["POST", "GET"])
def signin():
    username = request.json["user"]
    password = request.json["password"]
    api_key = request.json["api_key"]
    if api_key != apiKey:
        return "Invalid API Key", 401

    userData = json.loads(open(f"{pythonanywherePath}userData.json").read())
    for userId in userData:
        if userData[userId]["user"] == username:
            passC = password == userData[userId]["pass"]
            if passC == True:
                return userId, 200
            else:
                return "password", 403
    return "not found", 404


@app.route("/upload_image", methods=["POST"])
def upload_image():
    userid = request.form.get("user_id")
    api_key = request.form.get("api_key")
    if api_key != apiKey:
        return "Invalid API Key", 401
    imageData = json.loads(open(f"{pythonanywherePath}data.json").read())
    userData = json.loads(open(f"{pythonanywherePath}userData.json").read())

    if userid not in userData:
        return "User ID not found", 404

    foundUser = False
    index = ""
    for userIndex in imageData:
        if imageData[userIndex]["id"] == userid:
            foundUser = True
            index = str(userIndex)

    if foundUser == False:
        index = str(len(imageData))
        imageData[str(len(imageData))] = {"id": userid, "images": []}

    print("--------------------------------")
    print(imageData)

    image_string = request.form["picture"]
    image_data = base64.b64decode(image_string)
    image = Image.open(io.BytesIO(image_data))

    # image_file = request.files["picture"]
    # image_data = image_file.read()
    # image_base64 = base64.b64encode(image_data).decode("utf-8")
    # image = Image.open(io.BytesIO(image_data))

    image_name = random.randint(0, 999999999)
    file_path = f"{pythonanywherePath}static/assets/{image_name}.png"
    image.save(file_path, "PNG", optimize=True, quality=100)

    imageData[index]["images"].append(file_path)
    print(imageData)
    with open(f"{pythonanywherePath}data.json", "w") as jsonFile:
        json.dump(imageData, jsonFile, indent=2, separators=(",", ": "))

    return "ok", 200


@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "POST")
    return response

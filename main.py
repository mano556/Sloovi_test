from flask import Flask,render_template,request,make_response,jsonify,session
from flask_mongoengine import MongoEngine
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
import datetime
from functools import wraps


app=Flask(__name__)
app.config['SECRET_KEY'] = "##10##"
database_name="test"
# Mongo atlas linking
DB_URI="mongodb+srv://test:Test123@cluster0.quohhhr.mongodb.net/?retryWrites=true&w=majority"

app.config["MONGODB_HOST"]=DB_URI

db=MongoEngine()
db.init_app(app)
# Creation of user class 
class user(db.Document):
    user_id=db.IntField()
    first_name=db.StringField()
    last_name=db.StringField()
    email=db.StringField()
    password=db.StringField()

# creation of template class
class template(db.Document):
    template_id=db.IntField()
    template_name=db.StringField()
    subject=db.StringField()
    body=db.StringField()
# convert this  to json
    def to_json(self):
        return{
        "template_id":self.template_id,
        "template_name":self.template_name,
        "subject":self.subject,
        "body":self.body
        }

# Token creation
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=request.args.get("token")

        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']

        if not token:
            return jsonify({"message":"Token is missing!"}),401

        try:
            data=jwt.decode(token,app.config['SECRET_KEY'])
            current_user=user.objects(user_id=data['user_id']).first()
        except:
            return jsonify({'message':'Token is invalid'}),401

        return f(current_user, *args, **kwargs)

    return decorated

# Register route
@app.route("/register",methods=["POST"])
def register():
    if request.method=="POST":
        content=request.json
    hashed_password=generate_password_hash(content["password"],method='sha256')
    new_user=user(user_id=content['user_id'],first_name=content['first_name'],last_name=content['last_name'],email=content["email"],password=hashed_password)
    new_user.save()
    return make_response("New user is created",201)


# Login route
@app.route("/login")
def login():
    auth=request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify ',401,{'WWW-Authenticate':'Basic realm="Login required!"'})
    user_obj=user.objects(email=auth.username).first()
    if not user_obj:
        return make_response('could not verify ',401,{'WWW-Authenticate':'Basic realm="Login required!"'})
    if check_password_hash(user_obj.password,auth.password):
        token=jwt.encode({'user_id':user_obj.user_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30),},app.config['SECRET_KEY'])
        return jsonify({'token':token})
    return make_response('could not verify ',401,{'WWW-Authenticate':'Basic realm="Login required!"'})


# create new template route
@app.route("/template",methods=["POST"])
def create_new_template():
    if request.method=="POST":
        content=request.json
    template1=template( template_id=content['template_id'],template_name=content['template_name'],subject=content['subject'],body=content['body'])
    template1.save()
    return make_response("new template is created",201)


# Get all template route
@app.route("/template",methods=["GET"])
# @token_required
def get_all_template():  
    if request.method=="GET":
        templateData=[]
        for x in template.objects:
            templateData.append(x)
        return make_response(jsonify(templateData),200)
    
# Get specific template route
@app.route("/template/<template_id>",methods=["GET"])
# @token_required
def get_specific_template(template_id):
    if request.method=="GET":  
        template_obj=template.objects(template_id=template_id).first()
        if template_obj:
            return make_response(jsonify(template_obj.to_json()),200)
        else:
            return make_response("",404)
#Update template route
@app.route("/template/<template_id>",methods=["PUT"])
# @token_required
def Update_specific_template(template_id):
    
    if request.method=="PUT":  
        content=request.json
        template_obj=template.objects(template_id=template_id).first()
        template_obj.update( 
        template_name=content['template_name'],
        subject=content['subject'],
        body=content['body'])
        return make_response("",204)
#Delete template route
@app.route("/template/<template_id>",methods=["DELETE"])
# @token_required
def delete_specific_template(template_id):
    if request.method=="DELETE":
        template_obj=template.objects(template_id=template_id).first()
        template_obj.delete()
        return make_response("",204)


if __name__ == "__main__":
    app.run(debug=True)
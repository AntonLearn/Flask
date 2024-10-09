import flask
import schema
from flask import Flask
from flask_bcrypt import Bcrypt
from flask import jsonify, request
from models import Session, User, Adv
from pydantic import ValidationError
from flask.views import MethodView
from sqlalchemy.exc import IntegrityError
from settings import HOST_LOCATION, PORT_LOCATION, DEBUG


app = Flask('app')
bcrypt = Bcrypt(app)


def hash_password(password: str):
    password = password.encode()
    hashed_password = bcrypt.generate_password_hash(password)
    return hashed_password.decode()


def check_password(password: str, hashed_password: str):
    password = password.encode()
    hashed_password = hashed_password.encode()
    return bcrypt.check_password_hash(hashed_password, password)


class HttpError(Exception):

    def __init__(self, status_code: int, error_message: dict | str | list):
        self.status_code = status_code
        self.error_message = error_message


@app.errorhandler(HttpError)
def error_handler(er: HttpError):
    response = jsonify({"error": er.error_message})
    response.status_code = er.status_code
    return response


@app.before_request
def before_request():
    session = Session()
    request.session = session


@app.after_request
def after_request(http_response: flask.Response):
    request.session.close()
    return http_response


def validate(json_data: dict,
             schema_cls: type[schema.UpdateUser] | type[schema.CreateUser] |
                         type[schema.UpdateAdv]  | type[schema.CreateAdv]):
    try:
        return schema_cls(**json_data).dict(exclude_unset=True)
    except ValidationError as err:
        errors = err.errors()
        for error in errors:
            error.pop('ctx', None)
        raise HttpError(status_code=400, error_message=errors)


def get_user_by_id(user_id):
    user = request.session.get(User, user_id)
    if user is None:
        raise HttpError(status_code=404, error_message='User not found!')
    return user


def get_user_by_all():
    user_object_list = request.session.query(User).all()
    if not user_object_list:
        raise HttpError(status_code=404, error_message='Users not found!')
    return user_object_list


def add_user(user):
    request.session.add(user)
    try:
        request.session.commit()
    except IntegrityError:
        raise HttpError(status_code=409, error_message='User already exists!')
    return user


class UserView(MethodView):
    def get(self, user_id):
        if user_id is None:
            user_object_list = get_user_by_all()
            user_list = list()
            for user_object in user_object_list:
                user_list.append(user_object.dict)
            return jsonify(user_list)
        else:
            user_object = get_user_by_id(user_id)
            return jsonify(user_object.dict)

    def post(self):
        json_data = validate(request.json, schema.CreateUser)
        json_data["password"] = hash_password(json_data["password"])
        user = User(**json_data)
        user = add_user(user)
        return jsonify(user.dict)

    def patch(self, user_id):
        json_data = validate(request.json, schema.UpdateUser)
        if "password" in json_data:
            json_data["password"] = hash_password(json_data["password"])
        user_object = get_user_by_id(user_id)
        for field, value in json_data.items():
            setattr(user_object, field, value)
        user_object = add_user(user_object)
        return jsonify(user_object.dict)

    def delete(self, user_id):
        user_object = get_user_by_id(user_id)
        request.session.delete(user_object)
        request.session.commit()
        return jsonify({'status': 'deleted'})


def get_adv_by_id(adv_id):
    adv = request.session.get(Adv, adv_id)
    if adv is None:
        raise HttpError(status_code=404, error_message='Advertisement not found!')
    return adv


def get_adv_by_all():
    adv_object_list = request.session.query(Adv).all()
    if not adv_object_list:
        raise HttpError(status_code=404, error_message='Advertisements not found!')
    return adv_object_list


def add_adv(adv, password, user_id):
    user_object_list = request.session.query(User).all()
    if not user_object_list:
        raise HttpError(status_code=404, error_message='Users not found!')
    authorization = False
    user_found = False
    user_is_owner = False
    if user_id is None:
        for user_object in user_object_list:
            user_id_db = getattr(user_object, User.id.key)
            if adv.owner_id == user_id_db:
                user_found = True
                hashed_password = getattr(user_object, User.password.key)
                if check_password(password, hashed_password):
                    authorization = True
        if not user_found:
            raise HttpError(status_code=404, error_message='Owner not found!')
        if not authorization:
            raise HttpError(status_code=404, error_message='Owner is found but not authorized!')
    else:
        if user_id == adv.owner_id:
            user_is_owner = True
            for user_object in user_object_list:
                user_id_db = getattr(user_object, User.id.key)
                if adv.owner_id == user_id_db:
                    user_found = True
                    hashed_password = getattr(user_object, User.password.key)
                    if check_password(password, hashed_password):
                        authorization = True
        if not user_is_owner:
            raise HttpError(status_code=404, error_message='User is not owner!')
        if not user_found:
            raise HttpError(status_code=404, error_message='User is owner but not found!')
        if not authorization:
            raise HttpError(status_code=404, error_message='User is owner and found but not authorized!')
    request.session.add(adv)
    try:
        request.session.commit()
    except IntegrityError:
        raise HttpError(status_code=409, error_message='Advertisement already exists!')
    return adv


def delete_adv(adv, password, user_id):
    user_object_list = request.session.query(User).all()
    if not user_object_list:
        raise HttpError(status_code=404, error_message='Users not found!')
    authorization = False
    user_found = False
    user_is_owner = False
    if user_id is None:
        raise HttpError(status_code=404, error_message='User ID is missing!')
    else:
        if user_id == adv.owner_id:
            user_is_owner = True
            for user_object in user_object_list:
                user_id_db = getattr(user_object, User.id.key)
                if adv.owner_id == user_id_db:
                    user_found = True
                    hashed_password = getattr(user_object, User.password.key)
                    if check_password(password, hashed_password):
                        authorization = True
        if not user_is_owner:
            raise HttpError(status_code=404, error_message='User is not owner!')
        if not user_found:
            raise HttpError(status_code=404, error_message='User is owner but not found!')
        if not authorization:
            raise HttpError(status_code=404, error_message='User is owner and found but not authorized!')
    request.session.delete(adv)
    request.session.commit()
    return adv


class AdvView(MethodView):
    def get(self, adv_id):
        if adv_id is None:
            adv_object_list = get_adv_by_all()
            adv_list = list()
            for adv_object in adv_object_list:
                adv_list.append(adv_object.dict)
            return jsonify(adv_list)
        else:
            adv_object = get_adv_by_id(adv_id)
            return jsonify(adv_object.dict)

    def post(self):
        json_data = validate(request.json, schema.CreateAdv)
        adv_object = Adv(**json_data)
        password = request.headers['Authorization']
        adv_object = add_adv(adv_object, password, user_id=None)
        return jsonify(adv_object.dict)

    def patch(self, adv_id):
        json_data = validate(request.json, schema.UpdateAdv)
        adv_object = get_adv_by_id(adv_id)
        for field, value in json_data.items():
            setattr(adv_object, field, value)
        user_id = request.headers['Id']
        password = request.headers['Authorization']
        adv_object = add_adv(adv_object, password, user_id=int(user_id))
        return jsonify(adv_object.dict)

    def delete(self, adv_id):
        user_id = request.headers['Id']
        password = request.headers['Authorization']
        adv_object = get_adv_by_id(adv_id)
        delete_adv(adv_object, password, user_id=int(user_id))
        return jsonify({'status': 'deleted'})


user_view = UserView.as_view("user")
adv_view = AdvView.as_view("adv")

app.add_url_rule(rule="/user/", defaults={'user_id': None}, view_func=user_view, methods=['GET'])
app.add_url_rule(rule="/user/", view_func=user_view, methods=['POST'])
app.add_url_rule(rule="/user/<int:user_id>/", view_func=user_view, methods=['GET', 'PATCH', 'DELETE'])
app.add_url_rule(rule="/adv/", defaults={'adv_id': None}, view_func=adv_view, methods=['GET'])
app.add_url_rule(rule="/adv/", view_func=adv_view, methods=['POST'])
app.add_url_rule(rule="/adv/<int:adv_id>/", view_func=adv_view, methods=['GET', 'PATCH', 'DELETE'])

app.run(host=HOST_LOCATION, port=PORT_LOCATION, debug=DEBUG)

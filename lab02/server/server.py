from flask import Flask, abort, request, app, send_file
import json
import io
import threading


class Product:
    def __init__(self, attrs: dict):
        self.attrs = attrs
        self.icon_content = None

    def to_pretty_json(self):
        return json.dumps(self.attrs, indent=2)


the_products = []
the_product_mutex = threading.Lock()

app = Flask(__name__)


@app.route("/")
def index():
    return "Index Page"


@app.route("/product", methods=["POST"])
def add_product():
    try:
        json_product_data = json.loads(request.get_data())
        product_name = json_product_data["name"]
        product_description = json_product_data["description"]
    except:
        abort(400)
    with the_product_mutex:
        product = Product({
            "id": len(the_products),
            "name": product_name,
            "description": product_description,
        })
        the_products.append(product)
        return product.to_pretty_json()


@app.route("/product/<int:product_id>", methods=["GET", "PUT", "DELETE"])
def for_product(product_id: int):
    if product_id < 0 or product_id >= len(the_products):
        abort(404)
    with the_product_mutex:
        product = the_products[product_id]
        if product is None:
            abort(404)
        if request.method == "GET":
            return product.to_pretty_json()
        if request.method == "PUT":
            try:
                json_product_data = json.loads(request.get_data())
                specified_id = json_product_data.get("id")
                if specified_id is not None and specified_id != product_id:
                    abort(400)
            except:
                abort(400)
            new_name = json_product_data.get("name")
            if new_name is not None:
                product.attrs["name"] = new_name
            new_description = json_product_data.get("description")
            if new_description is not None:
                product.attrs["description"] = new_description
            return product.to_pretty_json()
        assert (request.method == "DELETE")
        the_products[product_id] = None
        return product.to_pretty_json()


@app.route("/products")
def get_all_products():
    with the_product_mutex:
        all_products = []
        for product in the_products:
            if product is None:
                continue
            all_products.append(product.attrs)
        return json.dumps(all_products, indent=2)


@app.route("/product/<int:product_id>/image", methods=["GET", "POST"])
def for_product_image(product_id: int):
    if product_id < 0 or product_id >= len(the_products):
        abort(404)
    with the_product_mutex:
        product = the_products[product_id]
        if product is None:
            abort(404)
        if request.method == "GET":
            if product.icon_content is None:
                abort(404)
            return send_file(io.BytesIO(product.icon_content), download_name=product.attrs["icon_filename"])
        assert (request.method == "POST")
        icon_file = request.files.get('icon')
        if icon_file is None:
            abort(400)
        product.attrs["icon_filename"] = icon_file.filename
        product.icon_content = icon_file.stream.read()
        return product.to_pretty_json()

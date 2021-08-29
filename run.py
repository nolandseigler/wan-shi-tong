from wan_shi_tong.app import create_app

if __name__ == "__main__":
    app = create_app("test_config")
    app.run(host="127.0.0.1", port=8080, debug=True, use_reloader=False)
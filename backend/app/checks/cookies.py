def analyse_cookies(response):
    cookies_raw = response.headers.get_list("set-cookie")
    results = []



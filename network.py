import time
import json
import os
import helpers
from pathlib import Path
from gql import Client
from gql.transport.aiohttp import AIOHTTPTransport

cache_dir = "./cache"
token_string = os.getenv("BOOST_API_TOKEN") or ""
token = f"ApiKey {token_string}"
# token = f"Bearer {token_string}"

if token_string == "":
    raise ValueError("Please provide a token")


def write_to_file(file_name, data):
    current_timestamp = int(time.time())
    file_name = f"{cache_dir}/{current_timestamp}-{file_name}.json"
    with open(file_name, "w") as file:
        json.dump(data, file, indent=4)


def is_within_two_hour_range(timestamp):
    current_timestamp = time.time()
    two_hours_ago = current_timestamp - 2 * 60 * 60
    return two_hours_ago <= timestamp


def read_file(file_name):
    directory = Path(cache_dir)
    for f in directory.iterdir():
        parsed_file_name = str(f).split("cache/")[1].split(".json")[0].split("-")
        time_of_file = parsed_file_name[0]
        label_of_file = parsed_file_name[1]

        if file_name != label_of_file:
            continue

        less_than_two_hours_old = is_within_two_hour_range(int(time_of_file))

        if less_than_two_hours_old == False:
            continue

        with open(f, "r") as file:
            return json.load(file)

    return False


def request_gql(options):

    if options.get("meta"):
        meta = options.get("meta")
        request = meta.get("request")
        org = meta.get("org")
        page = options.get("params").get("page")
        print(f"Calling {request} for {org} ~ page {page}...")

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Prefer": "safe",
        "Content-Type": "application/json",
        "Authorization": options.get("token") or token,
        "DNT": "1",
        "Connection": "keep-alive",
        "Origin": "https://admin-app.boostsecurity.io",
        "Sec-Fetch-Dest": "empty",
        "Sec-GPC": "1",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
    }
    transport = AIOHTTPTransport(url=options["url"], headers=headers)
    client = Client(transport=transport, fetch_schema_from_transport=True)
    return client.execute(options["query"], variable_values=options["params"])


def check_cache(options):
    label = options.get("label")
    page = options.get("params", {}).get("page", 1)
    file_label = f"{label}_{page}"
    result = {}

    cached_file = read_file(file_label)
    if cached_file != False:
        if options.get("meta"):
            meta = options.get("meta")
            request = meta.get("request")
            org = meta.get("org")
            page = options.get("params").get("page")
            print(f"Cache hit {request} for {org} ~ page {page}...")

        result = cached_file
    else:
        result = request_gql(options)
        write_to_file(file_label, result)

    return result


def paginate(options):
    result = None
    if options.get("no_cache") == True:
        result = request_gql(options)
    else:
        result = check_cache(options)

    post_execution = options.get("post_execution")
    if post_execution != None:
        post_execution(result)

    page_info_pointer = helpers.get_nested_value(
        result, options.get("page_info_pointer")
    )

    page_info_pointer = page_info_pointer.get("pageInfo", {}).get("hasNextPage", False)
    page = options.get("params", {}).get("page")

    if page_info_pointer:
        options["params"]["page"] = page + 1
        return paginate(options)

import requests, json


def detail_fetcher(isbn):
    details_book = requests.get(
        "https://openlibrary.org/api/books?bibkeys=ISBN:" + str(isbn) + "&jscmd=details&format=json").content
    details_book = json.loads(details_book.decode('utf-8'))
    details_book = details_book.get('ISBN:' + str(isbn))
    details_book = details_book.get('details')
    # Information to send to template
    title = details_book.get('title')
    first_sentence = details_book.get('first_sentence').get('value')
    open_lib_cover = "http://covers.openlibrary.org/b/isbn/" + str(isbn) + "-L.jpg"

    return {"title": title, "fs": first_sentence, "olc": open_lib_cover}


print(detail_fetcher('0380795272'))

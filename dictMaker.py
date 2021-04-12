import csv


def dictmaker():
    f = open('books.csv')
    reader = csv.reader(f)
    books_list = []
    for isbn, title, author, year in reader:
        book = {"isbn": isbn, "title": title, "author": author, "year": year}
        books_list.append(book)
    return books_list

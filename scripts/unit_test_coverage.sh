coverage run --branch -m unittest tests $@ && coverage html && open -a "Google Chrome" htmlcov/index.html 
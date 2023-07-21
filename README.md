# Welcome to the backend of the Career Center! test 2

This project contains the backend side for the Career Center.
This projects runs on Python with FastAPI framework.

## How to run the project on a docker:
To run this project just do:
```
docker-compose up
```

## How to run the project on developer mode:
To run this project just do:
```
uvicorn app.main:create_app --reload 
```

## How to generate documentation
In order to generate documentation for the project, go to the docs folder and execute the following command:
```
make html
```

Now we should be able to see the _build folder, with the index.html.

## Frontend side
The frontend for this project is in [this](https://github.com/gbh-tech/career-center-frontend) repo.

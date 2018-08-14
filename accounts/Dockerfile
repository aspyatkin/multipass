FROM python:3.7-alpine

WORKDIR /code
ADD . /code

EXPOSE 5000/tcp

RUN pip install -r requirements.txt

CMD ["python", "app.py"]

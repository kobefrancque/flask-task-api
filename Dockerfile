FROM python:3.13-slim

WORKDIR /flask_crud_api

COPY . .

RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["python", "app.py"]
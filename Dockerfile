FROM python:3.11.0

ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY poetry.lock pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install poetry && \
    poetry config virtualenvs.create false 

ARG DEV=false
RUN if [ "$DEV" = "true" ] ; then poetry install --with dev ; else poetry install --only main ; fi

COPY ./app/ ./fastapi-example/
COPY alembic.ini ./fastapi-example/
COPY ./migrations/ ./fastapi-example/
# COPY ./ml/model/ ./ml/model/

ENV PYTHONPATH "${PYTHONPATH}:/fastapi-example/app"

EXPOSE 8080
#CMD alembic upgrade head
CMD uvicorn main:app --host 0.0.0.0 --port 8080

FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
# tools/ is not optional: `python -m tools.reset_credentials` is the way back in
# when a saved Management address is wrong and nobody can sign in, and
# `python -m tools.run_review` is the headless review. Neither ran in a container
# that shipped only app/.
COPY tools ./tools
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]

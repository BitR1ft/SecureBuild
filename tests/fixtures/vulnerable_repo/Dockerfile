FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3 python3-pip openssh-server
EXPOSE 22 5000
COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt
CMD ["python3", "app.py"]

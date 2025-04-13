#!/bin/bash
# docker compose ps
#docker compose exec -it mitm /code/mitm/switch/switch  & # Runs already in start-up
docker compose exec -it insec python covert_receiver.py &
docker compose exec -it python-processor python main.py &
docker compose exec -it sec python covert_sender.py &
docker compose logs -f 

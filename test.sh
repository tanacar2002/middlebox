#!/bin/bash
# docker compose ps
#docker compose exec -it mitm /code/mitm/switch/switch  & # Runs already in start-up
docker compose exec -it insec bash -c 'python covert_receiver.py' &
docker compose exec -it python-processor bash -c 'python main.py' &
docker compose exec -it sec bash -c 'python covert_sender.py' &
docker compose logs -f 

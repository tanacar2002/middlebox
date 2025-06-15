#!/bin/bash
# docker compose ps
docker compose exec -it insec bash -c 'python covert_receiver_v2.py' &
docker compose exec -it python-processor bash -c 'python main.py' &
docker compose exec -it sec bash -c 'python covert_sender_v2.py' &
docker compose logs -f 

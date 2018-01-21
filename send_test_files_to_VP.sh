#!/bin/bash

sudo scp -oBatchMode=yes -i ~/id_rsa -r boxMap.py uwaterloo_boxMap@$1:
sudo scp -oBatchMode=yes -i ~/id_rsa -r do_tests.py uwaterloo_boxMap@$1:
sudo scp -oBatchMode=yes -i ~/id_rsa -r good_ppl uwaterloo_boxMap@$1:

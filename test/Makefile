TAG := mod_auth_openidc
DIR := /root/mod_auth_openidc
TARGET := test/test

docker: docker-run

docker-build:
	docker build -f test/Dockerfile -t $(TAG) .

docker-run: docker-build
	docker run --init --rm -p 443:443 -v $(PWD)/test/openidc.conf:/etc/apache2/conf-available/openidc.conf -it $(TAG) "apache2ctl start && tail -f /var/log/apache2/error.log"

docker-check: docker-build
	docker run --rm -it $(TAG) "cd $(DIR) && $(TARGET)"

#
# gdb
#

DOCKER_GDB_FLAGS := --cap-add=SYS_PTRACE --security-opt seccomp=unconfined

docker-gdb-check: docker-build
	docker run --rm $(DOCKER_GDB_FLAGS) -it $(TAG) "cd $(DIR) && gdb -ex run $(TARGET)"

#
# Valgrind
#

VALGRIND_FLAGS := --leak-check=full --read-inline-info=yes --keep-debuginfo=yes
	
docker-valgrind: docker-build
	docker run --rm -p 443:443 -v $(PWD)/test/openidc.conf:/etc/apache2/conf-available/openidc.conf -it $(TAG) "source /etc/apache2/envvars && valgrind $(VALGRIND_FLAGS) /usr/sbin/apache2 -X"

docker-valgrind-check: docker-build
	docker run --rm  -it $(TAG) "cd $(DIR) && valgrind $(VALGRIND_FLAGS) $(TARGET)"

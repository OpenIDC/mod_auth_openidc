TAG := mod_auth_openidc
DIR := /root/mod_auth_openidc
TARGET := test/test
FLAGS := --rm -it $(TAG)
APACHE_FLAGS := -p 80:80 -p 443:443 -v $(PWD)/test/openidc.conf:/etc/apache2/conf-available/openidc.conf -v $(PWD)/metadata/:/root/mod_auth_openidc/metadata/

docker: docker-run

docker-build:
	docker build -f test/Dockerfile -t $(TAG) .

docker-run: docker-build
	docker run --init ${APACHE_FLAGS} ${FLAGS} "apache2ctl start && tail -f /var/log/apache2/error.log"

docker-check: docker-build
	docker run ${FLAGS} "cd $(DIR) && $(TARGET)"

#
# gdb
#

DOCKER_GDB_FLAGS := --cap-add=SYS_PTRACE --security-opt seccomp=unconfined

docker-gdb: docker-build
	docker run ${APACHE_FLAGS} $(DOCKER_GDB_FLAGS) ${FLAGS}  "source /etc/apache2/envvars && gdb -ex run --args /usr/sbin/apache2 -X"
	
docker-gdb-check: docker-build
	docker run ${FLAGS} $(DOCKER_GDB_FLAGS) "cd $(DIR) && gdb -ex run $(TARGET)"

#
# Valgrind
#

VALGRIND_FLAGS := --leak-check=full --read-inline-info=yes --keep-debuginfo=yes
	
docker-valgrind: docker-build
	docker run ${APACHE_FLAGS} ${FLAGS} "source /etc/apache2/envvars && valgrind $(VALGRIND_FLAGS) /usr/sbin/apache2 -X"

docker-valgrind-check: docker-build
	docker run ${FLAGS} "cd $(DIR) && valgrind $(VALGRIND_FLAGS) $(TARGET)"

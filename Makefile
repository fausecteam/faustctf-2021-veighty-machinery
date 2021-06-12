SERVICE := veighty-machinery
DESTDIR ?= dist_root
SERVICEDIR ?= /srv/$(SERVICE)

.PHONY: install

build:
	$(MAKE) -C chall

install: build
	mkdir -p $(DESTDIR)$(SERVICEDIR)
	cp chall/veighty-machinery $(DESTDIR)$(SERVICEDIR)/
	mkdir -p $(DESTDIR)/etc/systemd/system
	cp chall/service/veighty-machinery@.service $(DESTDIR)/etc/systemd/system/
	cp chall/service/veighty-machinery.socket $(DESTDIR)/etc/systemd/system/
	cp chall/service/system-veighty-machinery.slice $(DESTDIR)/etc/systemd/system/
	cp 'chall/service/srv-veighty\x2dmachinery-data.mount' $(DESTDIR)/etc/systemd/system/

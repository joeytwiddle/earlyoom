GITVERSION=\"$(shell git describe --tags --dirty)\"
CFLAGS=-Wall -DGITVERSION=$(GITVERSION)

earlyoomd: main.c sysinfo.c
	$(CC) $(CFLAGS) -o earlyoom main.c sysinfo.c

clean:
	rm -f earlyoom

# For CentOS:

install:
	cp earlyoom -f /usr/local/bin/earlyoom
	cp earlyoom.service /etc/systemd/system/earlyoom.service
	systemctl enable earlyoom

uninstall:
	rm -f /usr/local/bin/earlyoom
	systemctl disable earlyoom
	rm -f /etc/systemd/system/earlyoom.service

# For Debian/Ubuntu:

install-initscript:
	cp earlyoom -f /usr/local/bin/earlyoom
	cp earlyoom.initscript /etc/init.d/earlyoom
	chmod a+x /etc/init.d/earlyoom
	update-rc.d earlyoom start 18 2 3 4 5 . stop 20 0 1 6 .

uninstall-initscript:
	rm -f /usr/local/bin/earlyoom
	rm -f /etc/init.d/earlyoom
	update-rc.d earlyoom remove

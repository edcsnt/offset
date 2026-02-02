# Copyright 2026 edcsnt. All rights reserved.
.POSIX:

SRC = offset
PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

clean:
	@echo $(SRC) does not need building or cleaning
install:
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin" "$(DESTDIR)$(MANPREFIX)/man1"
	cp $(SRC) "$(DESTDIR)$(PREFIX)/bin"
	gzip -c $(SRC).1 >"$(DESTDIR)$(MANPREFIX)/man1/$(SRC).1.gz" \
		|| cp $(SRC).1 "$(DESTDIR)$(MANPREFIX)/man1"
	-chmod 0755 "$(DESTDIR)$(PREFIX)/bin/$(SRC)"
	-chmod 0644 "$(DESTDIR)$(MANPREFIX)/man1/$(SRC).1.gz" \
		|| chmod 0644 "$(DESTDIR)$(MANPREFIX)/man1/$(SRC).1"
uninstall:
	rm -f -- "$(DESTDIR)$(PREFIX)/bin/$(SRC)" \
		"$(DESTDIR)$(MANPREFIX)/man1/$(SRC).1.gz" \
		"$(DESTDIR)$(MANPREFIX)/man1/$(SRC).1"

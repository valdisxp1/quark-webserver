# quark - simple web server

include config.mk

all: quark

quark: quark.o config.h config.mk
	${CC} -o $@ quark.o ${LDFLAGS}

quark.o: quark.c config.h config.mk
	${CC} -c ${CFLAGS} quark.c

config.h:
	@echo creating $@ from config.def.h
	@cp config.def.h $@

clean:
	rm -f quark quark.o quark-${VERSION}.tar.gz

dist: clean
	@echo creating dist tarball
	@mkdir -p quark-${VERSION}
	@cp -R LICENSE Makefile arg.h config.def.h config.mk quark.1 quark.c quark-${VERSION}
	@tar -cf quark-${VERSION}.tar quark-${VERSION}
	@gzip quark-${VERSION}.tar
	@rm -rf quark-${VERSION}

install: all
	@echo installing executable file to ${DESTDIR}${PREFIX}/bin
	@mkdir -p ${DESTDIR}${PREFIX}/bin
	@cp -f quark ${DESTDIR}${PREFIX}/bin
	@chmod 755 ${DESTDIR}${PREFIX}/bin/quark
	@echo installing manual page to ${DESTDIR}${MANPREFIX}/man1
	@mkdir -p ${DESTDIR}${MANPREFIX}/man1
	@cp quark.1 ${DESTDIR}${MANPREFIX}/man1/quark.1
	@chmod 644 ${DESTDIR}${MANPREFIX}/man1/quark.1

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/quark
	rm -f ${DESTDIR}${MANPREFIX}/man1/quark.1

.PHONY: all options clean dist install uninstall

CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = -shared -lpam -lcurl -ljson-c
TARGET = pam_brunnen_g.so
INSTALL_DIR = /lib/x86_64-linux-gnu/security

all: $(TARGET)

$(TARGET): pam_brunnen_g.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: $(TARGET)
	install -m 755 $(TARGET) $(INSTALL_DIR)/
	@echo "PAM module installed. Add to /etc/pam.d/ configs:"
	@echo "auth sufficient pam_brunnen_g.so"

uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)

clean:
	rm -f $(TARGET)

test:
	pamtester brunnen-g $(USER) authenticate
all: ctsync-pull ctsync-push

.PHONY: clean ctsync-pull ctsync-push

ctsync-pull: 
	cd ctsync-pull && go build

ctsync-push: 
	cd ctsync-push && go build

clean:
	rm -f ctsync-pull/ctsync-pull
	rm -f ctsync-push/ctsync-push

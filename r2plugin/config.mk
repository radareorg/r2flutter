EXTERNAL_PLUGINS+=r2flutter
# EXTERNAL_PLUGINS+=hi

.PHONY: r2flutter

r2flutter: p/r2flutter

p/r2flutter:
	cd p && git clone https://github.com/trufae/r2flutter

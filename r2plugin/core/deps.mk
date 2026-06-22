R2FLUTTER_CORE_WD=$(LIBR)/xps/p/r2flutter
CFLAGS+=-I$(R2FLUTTER_CORE_WD)/include
R2FLUTTER_CORE_OBJ= \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_app.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_dumper.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_snapshot.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_discovery.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_names.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_strings.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_data_image.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_it.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_xrefs.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_object.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_sbom.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_clusters.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_classes.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_model.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_parse.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_pool_modern.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_version.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_cid.o \
	$(R2FLUTTER_CORE_WD)/src/lib/dart_obf.o \
	$(R2FLUTTER_CORE_WD)/src/r2/flutter_analysis.o \
	$(R2FLUTTER_CORE_WD)/src/r2/core_flutter.o
EXTERNAL_STATIC_OBJS+=$(R2FLUTTER_CORE_OBJ)

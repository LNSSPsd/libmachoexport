#include <stdint.h>

struct macho_export_symbol {
	const char *symbol_name;
	uint32_t flags;
	uint32_t data; // offset of func / library ordinal / stub offset
	uint64_t data2;
	// if flags==EXPORT_SYMBOL_FLAGS_REEXPORT, data2 is char * to library name
	// if flags==EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, data2 is resolver offset
	// otherwise data2 is ignored
};

struct macho_export_symtab {
	struct macho_export_symbol *symbols;
	uint32_t cnt;
	uint32_t alloc_cnt;
};

struct macho_export_symtab *macho_export_create();
struct macho_export_symtab *macho_export_read(void *data, uint64_t size);
void macho_export_insert(struct macho_export_symtab *,const char*,uint32_t flags,uint32_t data, uint64_t data2);
struct macho_export_symbol *macho_export_find(struct macho_export_symtab *,const char *);
void macho_export_remove(struct macho_export_symtab *symtab,const char *symbol);
void *macho_export_make(struct macho_export_symtab *, uint32_t *);
void macho_export_free(struct macho_export_symtab *);
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "loader.h"
#include "macho-export.h"

struct macho_export_symtab *macho_export_create() {
	struct macho_export_symtab *ret=malloc(sizeof(struct macho_export_symtab));
	ret->symbols=malloc(16*sizeof(struct macho_export_symbol));
	ret->cnt=0;
	ret->alloc_cnt=16;
}

static inline uint64_t read_uleb128(void **ptr) {
	uint64_t ret=0;
	unsigned int shift=0;
	while(1) {
		unsigned char cur=*(unsigned char *)*ptr;
		ret|=((cur&0x7f)<<shift);
		(*ptr)++;
		if(!(cur&0x80))
			return ret;
		shift+=7;
		if(shift>56)
			abort();
	}
}

static inline void put_uleb128(void **ptr, uint64_t val) {
	while(1) {
		uint64_t cur=val&0x7f;
		val>>=7;
		if(val)
			cur|=0x80;
		*(unsigned char*)*ptr=(unsigned char)cur;
		++*ptr;
		if(!val)
			return;
	}
}

static void _read_entry(char *root,void *ptr,void *begin,void *end,struct macho_export_symtab *symtab) {
	if(ptr>end)
		abort();
	size_t root_len=strlen(root);
	uint64_t len=read_uleb128(&ptr);
	void *export_info=ptr;
	ptr+=len;
	unsigned char edges=*(unsigned char *)ptr;
	ptr++;
	for(int i=0;i<edges;i++) {
		size_t cur_len=strlen(ptr);
		char *buf=malloc(root_len+cur_len+1);
		strcpy(stpcpy(buf,root),ptr);
		ptr+=cur_len+1;
		uint64_t offset=read_uleb128(&ptr);
		_read_entry(buf,begin+offset,begin,end,symtab);
		free(buf);
	}
	if(!len)
		return;
	uint64_t flags=read_uleb128(&export_info);
	if(flags==EXPORT_SYMBOL_FLAGS_REEXPORT) {
		uint64_t d=read_uleb128(&export_info);
		char *lib_name=malloc(strlen(export_info)+1);
		strcpy(lib_name,export_info);
		macho_export_insert(symtab,root,flags,(uint32_t)d,(uint64_t)lib_name);
		return;
	}else if(flags==EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) {
		uint64_t a=read_uleb128(&export_info);
		uint64_t b=read_uleb128(&export_info);
		macho_export_insert(symtab,root,flags,(uint32_t)a,b);
		return;
	}
	macho_export_insert(symtab,root,flags,(uint32_t)read_uleb128(&export_info),0);
}

struct macho_export_symtab *macho_export_read(void *data,size_t size) {
	struct macho_export_symtab *symtab=macho_export_create();
	_read_entry("",data,data,data+size,symtab);
	return symtab;
}

void macho_export_insert(struct macho_export_symtab *symtab,const char *name,uint32_t flags,uint32_t data,uint64_t data2) {
	if(symtab->cnt==symtab->alloc_cnt) {
		symtab->alloc_cnt*=2;
		symtab->symbols=realloc(symtab->symbols,symtab->alloc_cnt*sizeof(struct macho_export_symbol));
	}
	struct macho_export_symbol *symbol=symtab->symbols+symtab->cnt;
	symtab->cnt++;
	size_t name_mem_len=strlen(name)+1;
	char *name_copy=malloc(name_mem_len);
	memcpy(name_copy,name,name_mem_len);
	symbol->symbol_name=name_copy;
	symbol->flags=flags;
	symbol->data=data;
	symbol->data2=data2;
}

struct macho_export_symbol *macho_export_find(struct macho_export_symtab *symtab,const char *name) {
	for(struct macho_export_symbol *i=symtab->symbols;i!=symtab->symbols+symtab->cnt;i++) {
		if(strcmp(i->symbol_name,name)==0)
			return i;
	}
	return NULL;
}

void macho_export_remove(struct macho_export_symtab *symtab, const char *symbol) {
	for(int i=0;i!=symtab->cnt;i++) {
		if(strcmp(symtab->symbols[i].symbol_name,symbol)==0) {
			struct macho_export_symbol *v=symtab->symbols+i;
			free((char*)v->symbol_name);
			if(v->flags==EXPORT_SYMBOL_FLAGS_REEXPORT&&v->data2)
				free((void*)v->data2);
			memcpy(symtab->symbols+i,symtab->symbols+i+1,(symtab->cnt-i-1)*sizeof(struct macho_export_symbol));
			symtab->cnt--;
			return;
		}
	}
}

static inline unsigned int _count_symbols_starting_with(char *str, size_t len, char **symbols) {
	unsigned int ret=0;
	for(char **i=symbols;*i;i++) {
		if(!len) {
			ret++;
			continue;
		}
		if(strlen(*i)<len)
			continue;
		if(memcmp(*i,str,len)==0)
			ret++;
	}
	return ret;
}

struct mnode {
	char *symbol;
	uint32_t len;
	uint32_t subcnt;
	struct mnode *subnodes;
	struct macho_export_symbol *symbol_entry;
	uint32_t preflight_base;
};

static void mnode_free(struct mnode *node) {
	for(int i=0;i<node->subcnt;i++) {
		mnode_free(node->subnodes+i);
	}
	free(node->subnodes);
}

static struct mnode *_mnode_insert(struct mnode *node, char *symbol, uint32_t len, uint32_t submax) {
	struct mnode *cur;
	if(node) {
		cur=node->subnodes+node->subcnt;
		node->subcnt++;
	}else{
		cur=malloc(sizeof(struct mnode));
	}
	cur->symbol=symbol;
	cur->len=len;
	cur->subcnt=0;
	if(submax) {
		cur->subnodes=malloc(sizeof(struct mnode)*submax);
	}else{
		cur->subnodes=NULL;
	}
	return cur;
}

static void _cut_symbol(char **symbols,char *symbol,struct mnode *node) {
	size_t slen=strlen(symbol);
	int last=_count_symbols_starting_with(symbol,1,symbols);
	int syms=_count_symbols_starting_with(NULL,0,symbols);
	char **csb=malloc(sizeof(char*)*(syms+1));
	for(int i=2;i<slen;i++) {
		int cur=_count_symbols_starting_with(symbol,i,symbols);
		if(cur!=last) {
			i--;
			//if(i==1) {
			//	printf("1!! %s\n",symbol);
			//	i--;
			//}
			//printf("%.*s: %d,%d\n",i,symbol,_count_symbols_starting_with(symbol,i-1,symbols),_count_symbols_starting_with(symbol,i,symbols));
			char **csbptr=csb;
			for(char **v=symbols;*v;v++) {
				if(strlen(*v)<i||memcmp(*v,symbol,i)) {
					//printf("CONT %s %s\n",*v,symbol);
					continue;
				}
				//printf("taking %s\n",*v);
				*csbptr=(*v)+i;
				*v=NULL;
				csbptr++;
			}
			*csbptr=NULL;
			char **sptr=symbols;
			for(char **i=symbols;i!=symbols+syms;i++) {
				if(*i) {
					*sptr=*i;
					sptr++;
				}
			}
			*sptr=NULL;
			int last_symcnt=csbptr-csb;
			//printf("%.*s [\n",i,symbol);
			struct mnode *cnode=_mnode_insert(node,symbol,i,last_symcnt);
			for(int i=0;i<last_symcnt;i++) {
				_cut_symbol(csb,csb[i],cnode);
				int scnt=_count_symbols_starting_with(NULL,0,csb);
				//printf("%d %d\n",last_symcnt,scnt);
				if(scnt!=last_symcnt) {
					//
					last_symcnt=scnt;
					i=-1;
					continue;
				}
			}
			for(char **v=csb;*v;v++) {
				//printf("%s\n",*v);
				if(!*v)
					continue;
				_mnode_insert(cnode,*v,strlen(*v),0);
			}
			//printf("]\n");
			free(csb);
			return;
		}
	}
	free(csb);
}

static inline unsigned int count_uleb128(uint64_t val) {
	if(!val)
		return 1;
	unsigned int ret=0;
	while(val) {
		ret++;
		val>>=7;
	}
	return ret;
}

static void _print_nodes(struct mnode *node) {
	printf("%.*s [\n",node->len,node->symbol);
	for(struct mnode *sub=node->subnodes;sub!=node->subnodes+node->subcnt;sub++) {
		_print_nodes(sub);
	}
	printf("]\n");
}

static unsigned int mnode_preflight(struct mnode *node,unsigned int offset) {
	unsigned int base=offset;
	struct macho_export_symbol *symbol=node->symbol_entry;
	if(symbol) {
		offset+=count_uleb128(symbol->flags);
		offset+=count_uleb128(symbol->data);
		if(symbol->flags==EXPORT_SYMBOL_FLAGS_REEXPORT) {
			offset+=strlen((char*)symbol->data2)+1;
			offset+=count_uleb128(offset-base);
		}else{
			if(symbol->flags==EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) {
				offset+=count_uleb128(symbol->data2);
			}
			offset+=count_uleb128(offset-base);
		}
	}else{
		offset++;
	}
	offset++;
	if(!node->subcnt)
		return offset-base;
	uint32_t remake_offset=offset;
	for(int i=0;i<node->subcnt;i++) {
		struct mnode *sub=node->subnodes+i;
		offset+=sub->len+1+1;
	}
	uint32_t remake_threshold=offset;
	uint32_t *all_offs=calloc(node->subcnt,sizeof(uint32_t));
	for(int i=0;i<node->subcnt;i++) {
		struct mnode *sub=node->subnodes+i;
		all_offs[i]=offset;
		int do_remake=0;
		uint32_t roff=remake_offset;
		for(int j=0;j<node->subcnt;j++) {
			struct mnode *sub=node->subnodes+j;
			roff+=sub->len+1;
			roff+=count_uleb128(all_offs[j]);
			if(j==node->subcnt-1&&roff>remake_threshold) {
				remake_threshold=roff;
				do_remake=1;
			}
		}
		if(do_remake) {
			i=-1;
			offset=remake_threshold;
			continue;
		}
		offset+=mnode_preflight(sub,offset);
	}
	node->preflight_base=all_offs[0];
	free(all_offs);
	return offset-base;
}

static void mnode_put_o(struct mnode *node,void **ptr,void *begin) {
	struct macho_export_symbol *symbol=node->symbol_entry;
	if(symbol) {
		char buf[32];
		char *bptr=buf;
		put_uleb128((void**)&bptr,symbol->flags);
		put_uleb128((void**)&bptr,symbol->data);
		if(symbol->flags==EXPORT_SYMBOL_FLAGS_REEXPORT) {
			uint64_t liblen=strlen((char*)symbol->data2);
			put_uleb128(ptr,(bptr-buf)+liblen+1);
			memcpy(*ptr,buf,bptr-buf);
			(*ptr)+=(bptr-buf);
			memcpy(*ptr,(void*)symbol->data2,liblen+1);
			(*ptr)+=liblen+1;
		}else{
			if(symbol->flags==EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) {
				put_uleb128((void**)&bptr,symbol->data2);
			}
			put_uleb128(ptr,bptr-buf);
			memcpy(*ptr,buf,bptr-buf);
			(*ptr)+=(bptr-buf);
		}
	}else{
		*(unsigned char *)*ptr=0;
		(*ptr)++;
	}
	*(unsigned char *)*ptr=node->subcnt;
	(*ptr)++;
	if(!node->subcnt)
		return;
	//printf("preflight base: %u\n",node->preflight_base);
	void *sub_ptr=begin+node->preflight_base;
	for(int i=0;i<node->subcnt;i++) {
		struct mnode *sub=node->subnodes+i;
		memcpy(*ptr,sub->symbol,sub->len);
		(*ptr)+=sub->len+1;
		*((unsigned char *)*ptr -1)=0;
		put_uleb128(ptr,sub_ptr-begin);
		mnode_put_o(sub,&sub_ptr,begin);
	}
	//printf("*ptr=%p sub_ptr=%p\n",*ptr,sub_ptr);
	*ptr=sub_ptr;
}

static void mnode_put(struct mnode *node,void **ptr,void *begin) {
	struct macho_export_symbol *symbol=node->symbol_entry;
	if(symbol) {
		char buf[32];
		char *bptr=buf;
		put_uleb128((void**)&bptr,symbol->flags);
		put_uleb128((void**)&bptr,symbol->data);
		if(symbol->flags==EXPORT_SYMBOL_FLAGS_REEXPORT) {
			uint64_t liblen=strlen((char*)symbol->data2);
			put_uleb128(ptr,(bptr-buf)+liblen+1);
			memcpy(*ptr,buf,bptr-buf);
			(*ptr)+=(bptr-buf);
			memcpy(*ptr,(void*)symbol->data2,liblen+1);
			(*ptr)+=liblen+1;
		}else{
			if(symbol->flags==EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) {
				put_uleb128((void**)&bptr,symbol->data2);
			}
			put_uleb128(ptr,bptr-buf);
			memcpy(*ptr,buf,bptr-buf);
			(*ptr)+=(bptr-buf);
		}
	}else{
		*(unsigned char *)*ptr=0;
		(*ptr)++;
	}
	*(unsigned char *)*ptr=node->subcnt;
	(*ptr)++;
	if(!node->subcnt)
		return;
	void *remake_ptr=*ptr;
	for(int i=0;i<node->subcnt;i++) {
		struct mnode *sub=node->subnodes+i;
		memcpy(*ptr,sub->symbol,sub->len);
		(*ptr)+=sub->len+1;
		*((unsigned char *)*ptr -1)=0;
		put_uleb128(ptr,0);
	}
	void *remake_threshold=*ptr;
	uint32_t *all_offs=calloc(node->subcnt,sizeof(uint32_t));
	for(int i=0;i<node->subcnt;i++) {
		struct mnode *sub=node->subnodes+i;
		all_offs[i]=*ptr-begin;
		int do_remake=0;
		void *rptr=remake_ptr;
		for(int j=0;j<node->subcnt;j++) {
			struct mnode *sub=node->subnodes+j;
			memcpy(rptr,sub->symbol,sub->len);
			rptr+=sub->len+1;
			*((unsigned char *)rptr -1)=0;
			put_uleb128(&rptr,all_offs[j]);
			if(j==node->subcnt-1&&rptr>remake_threshold) {
				remake_threshold=rptr;
				do_remake=1;
			}
		}
		if(do_remake) {
			i=-1;
			*ptr=remake_threshold;
			continue;
		}
		mnode_put(sub,ptr,begin);
	}
	free(all_offs);
}

uint32_t mnode_get_max_size(struct mnode *node) {
	int sz=node->len+8;
	for(int i=0;i<node->subcnt;i++) {
		sz+=mnode_get_max_size(node->subnodes+i);
	}
	return sz;
}

void mnode_load_symbol_entries(struct macho_export_symtab *symtab,struct mnode *node, const char *full_name) {
	node->symbol_entry=macho_export_find(symtab,full_name);
	for(int i=0;i<node->subcnt;i++) {
		struct mnode *subnode=node->subnodes+i;
		size_t sfnsz=strlen(full_name)+subnode->len+1;
		char *sfn=malloc(sfnsz);
		sfn[sfnsz-1]=0;
		memcpy(stpcpy(sfn,full_name),subnode->symbol,subnode->len);
		mnode_load_symbol_entries(symtab,subnode,sfn);
		free(sfn);
	}
}

void *macho_export_make(struct macho_export_symtab *symtab, uint32_t *size) {
	uint32_t max_len=0;
	for(struct macho_export_symbol *i=symtab->symbols;i!=symtab->symbols+symtab->cnt;i++) {
		max_len+=strlen(i->symbol_name)+16;
		if(i->flags==EXPORT_SYMBOL_FLAGS_REEXPORT&&i->data2)
			max_len+=strlen((char*)i->data2);
	}
	char **all_symbols=malloc(sizeof(char*)*(symtab->cnt+1));
	for(int i=0;i<symtab->cnt;i++) {
		all_symbols[i]=(char*)symtab->symbols[i].symbol_name;
	}
	all_symbols[symtab->cnt]=NULL;
	struct mnode *root=_mnode_insert(NULL,0,0,symtab->cnt);
	//printf("Invoking w symbol %s\n",all_symbols[0]);
	//_cut_symbol(all_symbols,all_symbols[0],root);
	int last_symcnt=symtab->cnt;
	for(int i=0;i<last_symcnt;i++) {
		//printf("Invoking w symbol %s\n",all_symbols[i]);
		_cut_symbol(all_symbols,all_symbols[i],root);
		int scnt=_count_symbols_starting_with(NULL,0,all_symbols);
		//printf("%d %d\n",scnt,last_symcnt);
		if(scnt!=last_symcnt) {
			last_symcnt=scnt;
			i=-1;
			continue;
		}
	}
	for(int i=0;i<last_symcnt;i++) {
		_mnode_insert(root,all_symbols[i],strlen(all_symbols[i]),0);
	}
	free(all_symbols);
	//_print_nodes(root);
	//for(char **sym=all_symbols;*sym;sym++) {
	//	printf("%s\n",*sym);
	//}
	mnode_load_symbol_entries(symtab,root,"");
	void *output=malloc(mnode_get_max_size(root));
	void *ptr=output;
	uint32_t psz=mnode_preflight(root,0);
	//printf("Preflight size=%u\n",psz);
	mnode_put(root,&ptr,output);
	mnode_free(root);
	free(root);
	*size=psz;
	return realloc(output,psz);
	//*size=ptr-output;
	//return realloc(output,ptr-output);
}

void macho_export_free(struct macho_export_symtab *symtab) {
	for(struct macho_export_symbol *i=symtab->symbols;i!=symtab->symbols+symtab->cnt;i++) {
		free((char*)i->symbol_name);
		if(i->flags==EXPORT_SYMBOL_FLAGS_REEXPORT&&i->data2)
			free((void*)i->data2);
	}
	free(symtab->symbols);
	free(symtab);
}

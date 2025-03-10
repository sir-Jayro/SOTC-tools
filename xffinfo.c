#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#ifdef unix
	#include <dirent.h>
#else
	#include <io.h>
#endif
#include <ctype.h>
#include <signal.h>

#include "xff.h"


typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char byte;

typedef struct{
	int is_dir;
	char *name;
	char *path;
	unsigned int size;
	int parent;
	int children_count;
} Dir_Entry;




char *XFF_SEC_TYPE_NAMES[] = {
	"SEC_NULL",
	"SEC_PROG",
	"SEC_SYMTAB",
	"SEC_STRTAB",
	"SEC_RELA",
	"",
	"",
	"",
	"SEC_NOBITS",
	"SEC_REL",
	"UNKNOWN"
};




void segv_sig(int sig){
	printf("\nERROR: Segment fault\n");
	exit(1);
}





void strtolower(char *str){
	for(int i=0; str[i]!='\0'; i++)
		str[i] = tolower(str[i]);
}






int get_dir_contents(char *dirname, int current_dir_entry,
		Dir_Entry **dir_entries, int *dir_entry_count, int recursive){

#ifdef unix
	char *tmp = malloc(strlen(dirname) + 2);
	sprintf(tmp, "%s/", dirname);
	
	//printf("Opening dir \"%s\"\n", tmp);
	DIR* dir = opendir(tmp);
	if(dir == NULL){
RET_ERR:;
		free(tmp);
		return 0;
	}
	//printf("Getting first entry\n");
	struct dirent* fileinfo = readdir(dir);
	if(fileinfo == NULL) goto RET_ERR;
	
#else
	char *tmp = malloc(strlen(dirname) + 3);
	sprintf(tmp, "%s/*", dirname);
	
	struct _finddata_t fileinfo;
	intptr_t cfilep = _findfirst(tmp, &fileinfo);

	if(cfilep == -1 || _findnext(cfilep, &fileinfo) == -1 ||
			_findnext(cfilep, &fileinfo) == -1){ // directory is empty
		free(tmp);
		_findclose(cfilep);
		return 0;
	}
#endif
	
	int count = 0;
	
	do{
		if(strcmp(fileinfo->d_name, ".") == 0){
			//printf("  skipping \".\"\n");
			fileinfo = readdir(dir);
			if(fileinfo == NULL) break;
		}
		if(strcmp(fileinfo->d_name, "..") == 0){
			//printf("  skipping \"..\"\n");
			fileinfo = readdir(dir);
			if(fileinfo == NULL) break;
		}
		
		(*dir_entries) = realloc(*dir_entries, sizeof(Dir_Entry) * ((*dir_entry_count) + 1));
		Dir_Entry *entry = &((*dir_entries)[(*dir_entry_count)++]);
		memset(entry, 0, sizeof(Dir_Entry));
		
#ifdef unix
		int name_len = strlen(fileinfo->d_name);
		entry->name = malloc(name_len + 1);
		strcpy(entry->name, fileinfo->d_name);
		//printf("%s\n", fileinfo->d_name);
#else
		int name_len = strlen(fileinfo.name);
		entry->name = malloc(name_len + 1);
		strcpy(entry->name, fileinfo.name);
#endif
		
		entry->parent = current_dir_entry;
		count++;
		
#ifdef unix
		if(fileinfo->d_type & DT_DIR){
#else
		if(fileinfo.attrib & _A_SUBDIR){
#endif
			int entry_i = (*dir_entry_count)-1;
			entry->is_dir = 1;
			entry->path = malloc(strlen(dirname) + strlen(entry->name) + 2);
			sprintf(entry->path, "%s/%s", dirname, entry->name);
			if(recursive){
				unsigned int children = get_dir_contents(entry->path,
						entry_i, dir_entries, dir_entry_count, recursive);
				(*dir_entries)[entry_i].children_count = children;
			}
			else (*dir_entries)[entry_i].children_count = 0;
			
			(*dir_entries)[entry_i].size = 0;
		}
		else{
			entry->is_dir = entry->children_count = 0;
			entry->path = malloc(strlen(dirname) + strlen(entry->name) + 2);
			sprintf(entry->path, "%s/%s", dirname, entry->name);
#ifdef unix
			struct stat ts;
			if(stat(entry->path, &ts) == 0)
				entry->size = ts.st_size;
			else entry->size = 0;
			
#else
			entry->size = fileinfo.size;
#endif
		}
#ifdef unix
	} while((fileinfo = readdir(dir)) != NULL);
	closedir(dir);
#else
	} while(_findnext(cfilep, &fileinfo) == 0);
	_findclose(cfilep);
#endif
	
	free(tmp);
	return count;
}






#ifndef __x86_64__
	#define INXFF(x, o) ((int)(x) + (o))
#else
	#define INXFF(x, o) ((long long)(x) + (o))
#endif






void Xff_Parse_Header(Xff *xff){
	// This is old code that would no longer work with the new "xff.h"
	
	/*xff->pFile_end = (byte*)xff + xff->file_size;
	
	xff->pExternals = (int*)((byte*)xff + xff->externals_offset);
	
	xff->pSymbols = (Xff_Symbol_Header*)((byte*)xff + xff->symbols_offset);
	xff->pSymbol_offsets = (int*)((byte*)xff + xff->symbol_offsets_offset);
	xff->pSymbol_names = (char*)((byte*)xff + xff->symbol_names_offset);
	
	xff->pSections = (Xff_Section_Header*)((byte*)xff + xff->sections_offset);
	xff->pSection_name_offsets = (int*)((byte*)xff + xff->section_name_offsets_offset);
	xff->pSection_names = (char*)((byte*)xff + xff->section_names_offset);
	
	xff->pRelocations = (Xff_Relocation_Header*)((byte*)xff + xff->relocations_offset);
	
	for(int i=0; i<xff->section_amount; i++)
		xff->pSections[i].pSource = ((byte*)xff + xff->pSections[i].offset);
	
	for(int i=0; i<xff->relocation_amount; i++){
		xff->pRelocations[i].addresses = (Xff_Relocation_Address*)((byte*)xff +
				xff->pRelocations[i].addresses_offset);
		xff->pRelocations[i].data = (Xff_Relocation_Data*)((byte*)xff +
				xff->pRelocations[i].data_offset);
	}*/
}




void Xff_Sec_Names(Xff *xff){
	printf("Sections:\n\n");
	for(int i=1; i<xff->sec_amount; i++){
		XffSectionHeader* sec = (XffSectionHeader*)INXFF(xff, xff->secs_off) + i;
		printf("  %s\n    Size: %i  Type: %s\n",
				(char*)INXFF(xff, xff->sec_names_off + ((uint*)INXFF(xff, xff->sec_name_offs_off))[i]),
				sec->size,
				(sec->type > SEC_REL)?
					XFF_SEC_TYPE_NAMES[10]:
					XFF_SEC_TYPE_NAMES[sec->type]);
	}
	printf("\n");
}



void Xff_Sym_Names(Xff *xff){
	printf("Symbols:\n\n  External: %i\n  Local: %i\n  Sector: %i\n  Total: %i\n\n",
			xff->external_sym_amount,
			xff->sym_amount - xff->external_sym_amount - xff->sec_sym_amount - 1,
			xff->sec_sym_amount,
			xff->sym_amount-1);
	
	for(int i=xff->sec_sym_amount+1; i<xff->sym_amount; i++){
		XffSymbolHeader* sym = (XffSymbolHeader*)INXFF(xff, xff->syms_off) + i;
		if(*((char*)INXFF(xff, xff->sym_names_off) + sym->name) != '\0')
			printf("  -%c  %s\n",
					(sym->section)?(SymbolBind(sym->info)?'g':'l'):'e',
					(char*)INXFF(xff, xff->sym_names_off) + sym->name);
	}
	printf("\n");
}


void Xff_Ext_Sym_Names(Xff *xff){
	printf("External Symbols: %i\n\n",
			xff->external_sym_amount);
	for(int i=0; i<xff->external_sym_amount; i++){
		printf("  %s\n",
				(char*)INXFF(xff, xff->sym_names_off) +
					((XffSymbolHeader*)INXFF(xff, xff->syms_off))[((uint*)INXFF(xff, xff->externals))[i]].name);
	}
	printf("\n");
}


void Xff_Loc_Sym_Names(Xff *xff){
	printf("Local Symbols: %i\n\n",
			xff->sym_amount - xff->external_sym_amount - xff->sec_sym_amount - 1);
	for(int i=xff->sec_sym_amount+1; i<xff->sym_amount; i++){
		XffSymbolHeader* sym = (XffSymbolHeader*)INXFF(xff, xff->syms_off) + i;
		if(sym->section != 0)
			printf("  %s\n", (char*)INXFF(xff, xff->sym_names_off) + sym->name);
	}
	printf("\n");
}






Xff *Xff_Open(char *filename){
	char *error_msg;
	
	FILE *file = fopen(filename, "rb");
	if(file == NULL){
		printf("ERROR: Failed to open file \"%s\"\n", filename);
		return NULL;
	}
	
	uint magic;
	if(fread(&magic, 1, 4, file) != 4 || (magic != XFF_IDENT && magic != XFF2_IDENT)){
	//	printf("ERROR: Not a valid XFF file \"%s\" %08x\n", filename, magic);
		fclose(file);
		return NULL;
	}
	
	fseek(file, 0, SEEK_END);
	int file_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	
	if(file_size < 0){
		printf("ERROR: File too large \"%s\"\n", filename);
		fclose(file);
		return NULL;
	}
	
	Xff *xff = malloc(file_size);
	if(xff == NULL){
		printf("ERROR: Memory Error\n");
		fclose(file);
		return NULL;
	}
	
	if(fread(xff, 1, file_size, file) != file_size){
		free(xff);
		fclose(file);
		return NULL;
	}
	fclose(file);
	
	Xff_Parse_Header(xff);
	
	return xff;
}


void find_section(Dir_Entry *root, int root_size, char *sec_name){
	int has_amount = 0;
	for(int i=0; i<root_size; i++){
		if(!root[i].is_dir){
			Xff *xff = Xff_Open(root[i].path);
			if(xff == NULL) continue;
			for(int j=1; j<xff->sec_amount; j++){
				if(strcmp((char*)INXFF(xff, xff->sec_names_off)+((uint*)INXFF(xff, xff->sec_name_offs_off))[j], sec_name) == 0){
					printf("  %s\n", root[i].path);
					has_amount++;
					break;
				}
			}
			free(xff);
		}
	}
	
	printf("\nFound: %i files with a \"%s\" section.\n", has_amount, sec_name);
}


void find_symbol(Dir_Entry *root, int root_size, char *sym_name, int def){
	int has_amount = 0;
	for(int i=0; i<root_size; i++){
		if(!root[i].is_dir){
			Xff *xff = Xff_Open(root[i].path);
			if(xff == NULL) continue;
			for(int j=1; j<xff->sym_amount; j++){
				XffSymbolHeader* sym = (XffSymbolHeader*)INXFF(xff, xff->syms_off) + j;
				if(strcmp((char*)INXFF(xff, xff->sym_names_off)+sym->name, sym_name) == 0){
					if(def){
						if(sym->section != 0){
							printf("  %s\n", root[i].path);
							has_amount++;
							break;
						}
					}
					else{
						printf("  %s\n", root[i].path);
						has_amount++;
						break;
					}
					
				}
			}
			free(xff);
		}
	}
	
	if(def){
		if(has_amount)
			printf("\nFound: file with \"%s\" symbol definition.\n", sym_name);
		else
			printf("\nSymbol \"%s\" definition not found.\n", sym_name);
	}
	else
		printf("\nFound: %i file with a \"%s\" symbol.\n", has_amount, sym_name);
}


// WARNING: Very slow
void find_missing_symbols(Dir_Entry *root, int root_size, char *file){
	Xff *from = Xff_Open(file);
	if(from == NULL){
		printf("\nERROR: File \"%s\" not a valid XFF file\n", file);
		return;
	}
	
	if(from->external_sym_amount == 0){
		printf("\nERROR: File has no external dependicies\n");
		return;
	}
	
	char* syms_found = malloc((from->external_sym_amount+7)>>3);
	if(syms_found == NULL){
		printf("\nERROR: Memory error\n");
		return;
	}
	memset(syms_found, 0, (from->external_sym_amount+7)>>3);
	
	int found = 0;
	
	int not_found = 0;
	
	uint* fromexts = (uint*)INXFF(from, from->externals_off);
	XffSymbolHeader* fromsyms = (XffSymbolHeader*)INXFF(from, from->syms_off);
	
	for(int i=0; found<from->external_sym_amount&&i<root_size; i++){
		if(!root[i].is_dir){
			Xff *xff = Xff_Open(root[i].path);
			if(xff == NULL) continue;
			
			for(int j=0; found<from->external_sym_amount && j<from->external_sym_amount; j++){
				if(syms_found[j>>3] & (1 << (j&7))) continue;
				XffSymbolHeader* fromsym = fromsyms + fromexts[j];
				char* sym_name = (char*)INXFF(from, from->sym_names_off) + fromsym->name;
				
				XffSymbolHeader* xffsyms = (XffSymbolHeader*)INXFF(xff, xff->syms_off);
				for(int k=1; k<xff->sym_amount; k++){
					if(strcmp((char*)INXFF(xff, xff->sym_names_off)+xffsyms[k].name, sym_name) == 0){
						if(xffsyms[k].section != 0){
							syms_found[j>>3] |= 1 << (j&7);
							found++;
							break;
						}
					}
				}
			}
			
			free(xff);
		}
		printf(" %.2f%% \r", (float)(i) / ((float)(root_size))*100);
	}
	
	for(int i=0; i<from->external_sym_amount; i++){
		if(!(syms_found[i>>3] & (1 << (i&7)))){
			printf("Failed to find symbol \"%s\"\n",
				(char*)INXFF(from, from->sym_names_off) + fromsyms[fromexts[i]].name);
			not_found++;
		}
	}
	
	free(syms_found);
	
	if(not_found == 0)
		printf("        \nNo symbols missing\n");
	else
		printf("        \nFailed to find %i symbols\n", not_found);
}








char *path = 0;

int show_sec_names = 0;
int show_sym_names = 0;
int show_ext_sym_names = 0;
int show_loc_sym_names = 0;

int find_sec = 0;
int find_sym = 0;
int find_sym_def = 0;
int find_missing = 0;
char *find_val = 0;


void parse_args(int argc, char *argv[]){
	if(argc == 1){
		printf("xffinfo [-ext -loc -sec -sym -find {symdef {symbol_name} sym {symbol_name} sec {section_name} missing {file_name}}] directory/file\n");
		printf("  WARNING: Only one option will work at a time\n"
				"\t-ext \tPrint all external symbols in a file\n"
				"\t-loc \tPrint all local symbols in a file\n"
				"\t-sec \tPrint all sections in a file\n"
				"\t-sym \tPrint all symbols in a file\n"
				"\t-find\tFind a value listed below in a directory of files (recursive)\n"
				"\t  symdef  Find the definition of symbol {symbol_name}\n"
				"\t  sym     Find uses of the symbol {symbol_name} in a directory of files (recursive)\n"
				"\t  sec     Find all files with a section {section_name} (recursive)\n"
				"\t  missing Find all symbols without a definition in all other files in a directory (recursive)\n");
		exit(0);
	}
	for(int i=1; i<argc; i++){
		if(argv[i][0] == '-')
			switch(argv[i][1]){
				case 'e':
				case 'E':
					strtolower(argv[i]);
					if(strcmp(argv[i], "-ext") == 0)
						show_ext_sym_names =1;
					else goto Unknown_Arg;
					break;
				
				case 'l':
				case 'L':
					strtolower(argv[i]);
					if(strcmp(argv[i], "-loc") == 0)
						show_loc_sym_names =1;
					else goto Unknown_Arg;
					break;
				
				case 's':
				case 'S':
					strtolower(argv[i]);
					if(strcmp(argv[i], "-sec") == 0)
						show_sec_names = 1;
					else if(strcmp(argv[i], "-sym") == 0)
						show_sym_names = 1;
					else goto Unknown_Arg;
					break;
				
				case 'f':
				case 'F':
					strtolower(argv[i]);
					if(strcmp(argv[i], "-find") != 0)
						goto Unknown_Arg;
					strtolower(argv[++i]);
					if(strcmp(argv[i], "symdef") == 0){
						find_sym_def = 1;
						find_sym = 1;
					}
					else if(strcmp(argv[i], "sec") == 0)
						find_sec = 1;
					else if(strcmp(argv[i], "sym") == 0)
						find_sym = 1;
					else if(strcmp(argv[i], "missing") == 0){
						find_missing = 1;
						find_sym = 1;
					}
					else goto Unknown_Arg;
					find_val = argv[++i];
					break;
				
				default:
Unknown_Arg:
					printf("ERROR: Unknown argument \"%s\"\n", argv[i]);
					exit(1);
			}
		else path = argv[i];
	}
}

int main(int argc, char *argv[]){
	signal(SIGSEGV, segv_sig);
	parse_args(argc, argv);
	
	if(path == NULL){
		//printf("");
		return 1;
	}
	
	
	
	if(find_sec || find_sym){
		Dir_Entry *root = 0;
		int root_size = 0;
		int file_count = get_dir_contents(path, -1, &root, &root_size, 1);
		if(root_size == 0){
			printf("ERROR: Failed to get directory contents for \"%s\"\n", path);
			exit(1);
		}
		printf("Searching through %i files...\n\n", root_size);
		
		if(find_sec)
			find_section(root, root_size, find_val);
		else if(find_sym){
			if(find_missing)
				find_missing_symbols(root, root_size, find_val);
			else
				find_symbol(root, root_size, find_val, find_sym_def);
		}
		
		free(root);
	}
	
	else if(show_sec_names || show_sym_names){
		Xff *xff = Xff_Open(path);
		if(xff == NULL){
			printf("ERROR: Not a valid XFF file \"%s\"\n", path);
			free(xff);
			return 1;
		}
		
		if(show_sec_names)
			Xff_Sec_Names(xff);
		if(show_sym_names){
			if(show_ext_sym_names)
				Xff_Ext_Sym_Names(xff);
			else if(show_loc_sym_names)
				Xff_Loc_Sym_Names(xff);
			else
				Xff_Sym_Names(xff);
		}
		
		free(xff);
	}
	
	else{
		Dir_Entry *root = 0;
		int root_size = 0;
		int file_count = get_dir_contents(path, -1, &root, &root_size, 1);
		if(root_size == 0){
			printf("ERROR: Failed to get directory contents for \"%s\"\n", path);
			exit(1);
		}
		printf("Searching through %i files...\n\n", root_size);
		
		
		int sizes_amount = 0;
		int* sizes = NULL;
		int* amount = NULL;
		
		for(int i=0; i<root_size; i++){
			if(!root[i].is_dir){
				Xff *xff = Xff_Open(root[i].path);
				if(xff == NULL) continue;
				
				int size = -1;
				
				XffSymbolHeader* sym = (XffSymbolHeader*)INXFF(xff, xff->syms_off) + 1 + xff->sec_sym_amount;
				for(int j=1+xff->sec_sym_amount; j<xff->sym_amount; j++){
					XffSymbolHeader* tsym = (XffSymbolHeader*)INXFF(xff, xff->syms_off) + j;
					if(tsym->size > 0 && tsym->section == 1 &&
							(uint)tsym->address == xff->entry_off && 
							SymbolType(tsym->info) == SYM_FUNC){
						sym = tsym;
						break;
					}
				}
				
				if(sym->size <= 0 || sym->section != 1 || (uint)sym->address != xff->entry_off || SymbolType(sym->info) != 1){
					free(xff);
					continue;
				}
				
				//printf("%s ", (char*)INXFF(xff, sym_names_off)+sym->name);
				
				size = sym->size;
				
				XffSectionHeader* sec = (XffSectionHeader*)INXFF(xff, xff->secs_off) + sym->section;
				
				int value = *(int*)INXFF(xff, sec->offset + sym->address + 24);
				
				if(value > 1)
					printf("%s ", root[i].name);
				
				for(int k=0; k<sizes_amount; k++){
					if(sizes[k] == value){
						amount[k]++;
						free(xff);
						continue;
					}
				}
				
				sizes = realloc(sizes, sizeof(int*) * (sizes_amount + 1));
				amount = realloc(amount, sizeof(int*) * (sizes_amount + 1));
				if(sizes == NULL || amount == NULL){
					printf("ERROR: Memory error\n");
					exit(1);
				}
				sizes[sizes_amount] = value;
				amount[sizes_amount++] = 1;
					
			//	if(size == 52)
			//		printf("%s ", root[i].name);
				
				free(xff);
			}
		}
		
		printf("\n\n");
		for(int i=0; i<sizes_amount; i++)
			printf("%i - %i\n", sizes[i], amount[i]);
		
		
		free(root);
	}
	
	return 0;
}



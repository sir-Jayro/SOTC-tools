#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "xff.h"
#include "elf.h"


/******** WARNING ********
	
	This is still a WIP (work in progress)
	Some thing still don't work properly
	
*************************/


/***** TODO

	try and merge all the rodata sections into one
	make sure all local relocations are at the end
	make sure local and global relocations are seperate
	have an option for importing a map to add absolute addresses to matching symbols (for use with KERNEL.XFF)
	have an option to NOT strip out unneeded symbols and sections
	
	
	make a list of which sections are relocations and if they have local/global relocations

******/


/*
execution path

	analyze the elf file
		make list of sections
			ignore any unknown sections or 0 size sections
	start building xff
		create header struct
		get offsets
	convert to xff
		build xff file structure
		start filling in data and updating offsets
	write file
	clean up
*/



void sighandler(int sig){
	printf("\nERROR: Segment fault\n");
	fflush(stdout);
	exit(1);
}



int main(int argc, char** argv){
	signal(SIGSEGV, sighandler);
	
	char* filename = NULL;
	char* outfilename = NULL;
	int silent = 0;
	char* entry_sym = "main";
	int is_xff2 = 0;
	
// Parse the arguments
	for(int i=1; i<argc; i++){
		if(*argv[i] == '-'){	// Check for options
			switch(argv[i][1]){
				case 's':		// Silent mode
				case 'S':
					silent = 1;
					break;
				
				case 'e':		// The entry function name
				case 'E':
					entry_sym = argv[++i];
					break;
				
				case 'o':		// The name of the created xff file
				case 'O':
					outfilename = argv[++i];
					break;
				
				case '2':		// Makes an Xff2 file instead
					is_xff2 = 1;
					break;
				
				default:
					printf("\nWARNING: Unknown option [%s]\n", argv[i]);
			}
		}
		else{
			if(filename != NULL)
				printf("\nWARNING: Filename already defined, using newest one (\"%s\")\n", argv[i]);
			filename = argv[i];
		}
	}
	
	if(argc < 2){
		printf("elf2xff [-seo2] filename\n");
		return 0;
	}
	
	if(filename == NULL){
		printf("\nERROR: No input file\n");
		return 1;
	}
	
	
// Check and read in the elf file
	FILE* inf = fopen(filename, "rb");
	if(inf == NULL){
		printf("\nERROR: Failed to open file \"%s\"\n", filename);
		return 1;
	}
	
	fseek(inf, 0, SEEK_END);
	int filesize = ftell(inf);
	fseek(inf, 0, SEEK_SET);
	if(filesize < sizeof(Elf))
		goto NOT_VALID_ELF;
	
	Elf tmpelf = {0};
	if(fread(&tmpelf, 1, sizeof(Elf), inf) != sizeof(Elf))
		goto NOT_VALID_ELF;
	
	if(*(int*)&tmpelf != ELFMAG || tmpelf.machine != EM_MIPS){
NOT_VALID_ELF:;
		printf("\nERROR: Not a valid elf file\n");
		fclose(inf);
		return 1;
	}
	
	
	Elf* elf = malloc(filesize);
	if(elf == NULL){
MEMERR:;
		printf("\nERROR: Memory error\n");
		return 1;
	}
	fseek(inf, 0, SEEK_SET);
	if(fread(elf, 1, filesize, inf) != filesize){
		printf("\nERROR: Error reading file \"%s\"\n", filename);
		return 1;
	}
	fclose(inf);
	

// Macro to aid in getting values from the elf file
#ifndef __x86_64__
	#define INELF(x) ((int)elf + (x))
#else
	#define INELF(x) ((long long)elf + (x))
#endif
	
	
	
	
	
	Xff xff = {
		.ident = (is_xff2) ? XFF2_IDENT : XFF_IDENT,
		.sym_amount = 1,
		.sec_amount = 1,
		
		// Somewhere in the game code it checks if a pointer has a 4 in the top nibble. so all pointers need this
		.externals = 0x40000000,
		.syms = 0x40000000,
		.sym_names = 0x40000000,
		.secs = 0x40000000,
		.sym_offs = 0x40000000,
		.rels = 0x40000000,
		.sec_name_offs = 0x40000000,
		.sec_names = 0x40000000
	};
	
	int xff_section_names_len = 1;
	int xff_symbol_names_len = 1;
	
	int entry_sym_id = 0;
	
	int elf_sym_tab_i = 0;
	
	
// get the elf string table
	if(elf->str_tab_entry_num == 0){
		printf("ERROR: Missing section string table\n");
		return 1;
	}
	
	char* shstrtab = (char*)INELF(((ElfSection*)INELF(elf->sec_head_offset) + elf->str_tab_entry_num)->offset);
	
	
// parse the elf sections
	XffSectionHeader** xff_sections = malloc(sizeof(void*) * elf->sec_entry_count);
	ElfSection** elf_sections = malloc(sizeof(void*) * elf->sec_entry_count);
	if(xff_sections == NULL || elf_sections == NULL) goto MEMERR;
	memset(xff_sections, 0, sizeof(void*) * elf->sec_entry_count);
	memset(elf_sections, 0, sizeof(void*) * elf->sec_entry_count);
	
	for(int i=1; i<elf->sec_entry_count; i++){
		ElfSection* eSec = (ElfSection*)INELF(elf->sec_head_offset) + i;
		if(eSec->type == SHT_NULL || eSec->size == 0) continue;
		if(eSec->type <= SHT_RELA || eSec->type == SHT_NOBITS || eSec->type == SHT_REL){
			if(eSec->type == SHT_PROGBITS && (eSec->flags & SHF_ALLOC) == 0) continue;
			if(eSec->type == SHT_RELA || eSec->type == SHT_REL){
				if(elf_sections[eSec->info] == NULL) continue;
				// TODO: make a list of sections and put only the rels in it
				xff.rel_amount++;
			}
			XffSectionHeader* xSec = malloc(sizeof(XffSectionHeader));
			if(xSec == NULL) goto MEMERR;
			*xSec = (XffSectionHeader){
				.size = (eSec->type != SHT_REL && eSec->type != SHT_RELA) ? eSec->size : 0,
				.alignment = (eSec->type == SHT_PROGBITS || eSec->type == SHT_NOBITS) ? 8 : eSec->align,
				.type = eSec->type,
				.alloc = eSec->type == SHT_NOBITS,
				
				.data = 0x40000000,
				.source = 0x40000000
			};
			
			elf_sections[i] = eSec;
			
			if(eSec->type != SHT_RELA && eSec->type != SHT_REL){
				xff_sections[i] = xSec;
				xff.sec_amount++;
				
				if(!silent)
					printf("  %-2i: %s\n", i, shstrtab+eSec->name);
				int nlen = strlen(shstrtab+eSec->name);
				xff_section_names_len += nlen > 0 ? (nlen + 1) : 0;
			}
			if(eSec->type == SHT_SYMTAB)
				elf_sym_tab_i = i;
		}
	}
	
	if(elf_sym_tab_i == 0){
		printf("ERROR: Elf has no symbol table\n");
		return 1;
	}
	
	
	// parse the elf symbols
	
	int elf_sym_count = elf_sections[elf_sym_tab_i]->size / elf_sections[elf_sym_tab_i]->entry_size;
	
	XffSymbolHeader** xff_symbols = malloc(sizeof(void*) * elf_sym_count);
	ElfSymbol** elf_symbols = malloc(sizeof(void*) * elf_sym_count);
	if(xff_symbols == NULL || elf_symbols == NULL) goto MEMERR;
	memset(xff_symbols, 0, sizeof(void*) * elf_sym_count);
	memset(elf_symbols, 0, sizeof(void*) * elf_sym_count);
	
	char* strtab = (char*)INELF(elf_sections[elf_sections[elf_sym_tab_i]->link]->offset);
	
	if(!silent)
		printf("\n");
	for(int i=1; i<elf_sym_count; i++){
		ElfSymbol* eSym = (ElfSymbol*)INELF(elf_sections[elf_sym_tab_i]->offset) + i;
		int type = ELF32_ST_TYPE(eSym->info);
		if(type > STT_SECTION) continue;
		if(eSym->section != SYMSEC_ABS && (eSym->section < 0 || eSym->section > elf_sym_count)) continue;
		if(type == STT_SECTION && elf_sections[eSym->section] == NULL) continue;
//		if(eSym->section == SHN_COMMON){
//			printf("WARNING: SHN_COMMON in use, but is unimplemented\n");
//			continue;
//		}
		XffSymbolHeader* xSym = malloc(sizeof(XffSymbolHeader));
		if(xSym == NULL) goto MEMERR;
		
		*xSym = (XffSymbolHeader){
			.address = eSym->value,
			.size = eSym->size,
			.info = eSym->info
		};
		
		if(eSym->section != 0){
			if(eSym->section != SYMSEC_ABS){
				for(int j=1, k=1; j<elf->sec_entry_count; j++){
					if(j == eSym->section){
						xSym->section = k;
						break;
					}
					if(xff_sections[j] != NULL) k++;
				}
			}
			else
				xSym->section = eSym->section;
		}
	//	printf("Sym:%i  %i - %i\n", i, eSym->section, xSym->section);
		
		elf_symbols[i] = eSym;
		xff_symbols[i] = xSym;
		
		xff.sym_amount++;
		if(type == STT_SECTION) xff.sec_sym_amount++;
		else if(ELF32_ST_BIND(eSym->info) == STB_GLOBAL){
			if(eSym->section == 0) xff.external_sym_amount++;
			int nlen = strlen(strtab+eSym->name);
			if(nlen == 0) xSym->name = 0;
			else{
				xSym->name = xff_symbol_names_len;
				xff_symbol_names_len += nlen + 1;
			}
		}
		
		
		if(strcmp(entry_sym, strtab+eSym->name) == 0){
		//	printf("Found entry sym: %i - %i - %i\n", i, xSym->section, (int)xSym->address);
			xff.entry_off = (int)xSym->address;
			entry_sym_id = i;
		}
		
		
		if(!silent)
			printf("  %-4i: %c - %s\n", i, ELF32_ST_BIND(eSym->info)==STB_LOCAL?'l':eSym->size==0?'e':'g', strtab+eSym->name);
	}
	
	
	// parse elf relocations
	if(!silent)
		printf("\nRelocations...");
	XffRelocationHeader** xff_relocations = NULL;
	ElfSection** elf_relocations = NULL;
	
	if(xff.rel_amount > 0){
		xff_relocations = malloc(sizeof(void*) * xff.rel_amount);
		elf_relocations = malloc(sizeof(void*) * xff.rel_amount);
		if(xff_relocations == NULL || elf_relocations == NULL) goto MEMERR;
		memset(xff_relocations, 0, sizeof(void*) * xff.rel_amount);
		memset(elf_relocations, 0, sizeof(void*) * xff.rel_amount);
		
		for(int i=1, j=0; i<elf->sec_entry_count; i++){
			ElfSection* eSec = elf_sections[i];
			if(eSec == NULL || (eSec->type != SHT_REL && eSec->type != SHT_RELA)) continue;
			
			XffRelocationHeader* xRel = malloc(sizeof(XffRelocationHeader));
			if(xRel == NULL) goto MEMERR;
			
			*xRel = (XffRelocationHeader){
				.type = eSec->type,
				.amount = eSec->size / eSec->entry_size,
				
				.rels = 0x40000000,
				.addends = 0x40000000
			};
			
			for(int j=1, k=1; j<elf->sec_entry_count; j++){
				if(j == eSec->info){
					xRel->section = k;
					break;
				}
				if(xff_sections[j] != NULL) k++;
			}
			
			elf_relocations[j] = eSec;
			xff_relocations[j++] = xRel;
		}
	}
	
	if(!silent)
		printf("done\n\nGetting offsets...");
	
	xff.file_size = sizeof(Xff);
	
	xff.sec_name_offs_off = xff.file_size;
	xff.file_size += 4 * xff.sec_amount;
	
	xff.secs_off = xff.file_size;
	xff.file_size += sizeof(XffSectionHeader) * xff.sec_amount;
	
	xff.sym_offs_off = xff.file_size;
	xff.file_size += sizeof(int) * xff.sym_amount;
	
	xff.rels_off = xff.file_size;
	xff.file_size += sizeof(XffRelocationHeader) * xff.rel_amount;
	
	xff.externals_off = xff.file_size;
	xff.file_size += sizeof(int) * xff.external_sym_amount;
	
	xff.sec_names_off = xff.file_size;
	xff.file_size += (xff_section_names_len + 3) & ~3;
	
	for(int i=1; i<elf->sec_entry_count; i++){
		ElfSection* sec = elf_sections[i];
		if(sec == NULL || sec->type != SHT_PROGBITS) continue;
		xff.file_size = (xff.file_size + 7) & ~7;
		xff_sections[i]->offset = xff.file_size;
		xff.file_size += sec->size;
	}
	xff.file_size = (xff.file_size + 3) & ~3;
	
	xff.syms_off = xff.file_size;
	xff.file_size += sizeof(XffSymbolHeader) * xff.sym_amount;
	
	xff.sym_names_off = xff.file_size;
	xff.file_size += (xff_symbol_names_len + 3) & ~3;
	
	for(int i=0; i<xff.rel_amount; i++){
		xff_relocations[i]->rels_off = xff.file_size;
		xff.file_size += sizeof(XffRelocation) * xff_relocations[i]->amount;
	}
	
	for(int i=0; i<xff.rel_amount; i++){
		xff_relocations[i]->addends_off = xff.file_size;
		xff.file_size += sizeof(XffRelocationAddend) * xff_relocations[i]->amount;
	}
	
	if(!silent)
		printf("done\n\nBuilding XFF");
	
	
	char* out = malloc(xff.file_size);
	if(out == NULL) goto MEMERR;
	memset(out, 0, xff.file_size);
	
	// header
	memcpy(out, &xff, sizeof(Xff));
	
	if(!silent)
		printf(".");
	// section name offsets
	int next_name_i = 1;
	for(int i=1, j=1; i<elf->sec_entry_count; i++){
		ElfSection* eSec = elf_sections[i];
		if(xff_sections[i] == NULL) continue;
		
		int ni = next_name_i;
		int nlen = strlen(shstrtab + eSec->name);
		if(nlen == 0) ni = 0;
		else next_name_i += nlen + 1;
		
		*((unsigned int*)(out + xff.sec_name_offs_off) + j) = ni;
		j++;
	}
	
	if(!silent)
		printf(".");
	// sections
	for(int i=1, j=1; i<elf->sec_entry_count; i++){
		XffSectionHeader* xSec = xff_sections[i];
		if(xSec == NULL) continue;
		if(xSec->type == SEC_STRTAB){
			if(i == elf->str_tab_entry_num){
				xSec->offset = xff.sec_names_off;
				xSec->size = xff_section_names_len;
			}
			else{
				xSec->offset = xff.sym_names_off;
				xSec->size = xff_symbol_names_len;
			}
		}
		else if(xSec->type == SEC_SYMTAB){
			xSec->offset = xff.syms_off;
			xSec->size = xff.sym_amount * sizeof(XffSymbolHeader);
		}
		memcpy((XffSectionHeader*)(out + xff.secs_off) + j, xSec, sizeof(XffSectionHeader));
		j++;
	}
	
	if(!silent)
		printf(".");
	// symbol offsets
	for(int i=1, j=1; i<elf_sym_count; i++){
		XffSymbolHeader* xSym = xff_symbols[i];
		if(xSym == NULL) continue;
		ElfSymbol* eSym = elf_symbols[i];
		int type = SymbolType(xSym->info);
		if(type > SYM_SEC) continue;
		if(eSym->section != SYMSEC_ABS && (eSym->section < 0 || eSym->section > elf->sec_entry_count)) continue;
		if(type == SYM_SEC && elf_sections[eSym->section] == NULL) continue;
	//	if(xSym->section == SHN_COMMON) continue;
		*((unsigned int*)(out + xff.sym_offs_off) + j) = (unsigned int)xSym->address;
		j++;
	}
	
	if(!silent)
		printf(".");
	// relocation headers
	for(int i=0; i<xff.rel_amount; i++)
		memcpy((XffRelocationHeader*)(out + xff.rels_off) + i, xff_relocations[i], sizeof(XffRelocationHeader));
	
	if(!silent)
		printf(".");
	// external symbol indexes
	for(int i=1, j=0, k=0; i<elf_sym_count; i++){
		XffSymbolHeader* xSym = xff_symbols[i];
		if(xSym == NULL) continue;
		ElfSymbol* eSym = elf_symbols[i];
		int type = SymbolType(xSym->info);
		if(type > SYM_SEC) continue;
		if(eSym->section != SYMSEC_ABS && (eSym->section < 0 || eSym->section > elf->sec_entry_count)) continue;
		if(type == SYM_SEC && elf_sections[eSym->section] == NULL) continue;
		k++;
		if(SymbolBind(xSym->info) != SYM_GLOBAL || xSym->size > 0 || xSym->section != 0) continue;
		*((unsigned int*)(out + xff.externals_off) + j) = k;
		j++;
	}
	
	if(!silent)
		printf(".");
	// section names
	next_name_i = xff.sec_names_off + 1;
	for(int i=1; i<elf->sec_entry_count; i++){
		ElfSection* eSec = elf_sections[i];
		if(xff_sections[i] == NULL) continue;
		int nlen = strlen(shstrtab+eSec->name);
		if(nlen > 0){
			strcpy(out + next_name_i, shstrtab+eSec->name);
			next_name_i += nlen + 1;
		}
	}
	
	if(!silent)
		printf(".");
	// section data
	for(int i=1, j=1; i<elf->sec_entry_count; i++){
		XffSectionHeader* xSec = xff_sections[i];
		if(xSec == NULL || xSec->type != SEC_PROG) continue;
		memcpy(out + xSec->offset, (void*)INELF(elf_sections[i]->offset), xSec->size);
		j++;
	}
	
	if(!silent)
		printf(".");
	// symbols
	for(int i=1, j=1; i<elf_sym_count; i++){
		XffSymbolHeader* xSym = xff_symbols[i];
		if(xSym == NULL) continue;
		ElfSymbol* eSym = elf_symbols[i];
		int type = SymbolType(xSym->info);
		if(type > SYM_SEC) continue;
		if(eSym->section != SYMSEC_ABS && (eSym->section < 0 || eSym->section > elf->sec_entry_count)) continue;
		if(type == SYM_SEC && elf_sections[eSym->section] == NULL) continue;
	//	if(xSym->section == SHN_COMMON) continue;
		memcpy((XffSymbolHeader*)(out + xff.syms_off) + j, xSym, sizeof(XffSymbolHeader));
		j++;
	}
	
	if(!silent)
		printf(".");
	// symbol names
	next_name_i = 1;
	for(int i=1; i<elf_sym_count; i++){
		XffSymbolHeader* xSym = xff_symbols[i];
		if(xSym == NULL) continue;
		ElfSymbol* eSym = elf_symbols[i];
		int type = SymbolType(xSym->info);
		if(type > SYM_SEC) continue;
		if(eSym->section != SYMSEC_ABS && (eSym->section < 0 || eSym->section > elf->sec_entry_count)) continue;
		if(type == SYM_SEC && elf_sections[eSym->section] == NULL) continue;
		if(xSym->name == 0) continue;
		int nlen = strlen(strtab + eSym->name);
		if(nlen > 0){
			if(xSym->name != next_name_i)
				printf("WARNING: Symbol name offset mismatch\n");
			strcpy(out + xff.sym_names_off + next_name_i, strtab+eSym->name);
			next_name_i += nlen + 1;
		}
	}
	
	if(!silent)
		printf(".");
	// relocation addresses and data
	for(int i=0; i<xff.rel_amount; i++){
		XffRelocationHeader* xRel = xff_relocations[i];
		ElfSection* eSec = elf_relocations[i];
		pElfRelocation eRel = {(void*)INELF(eSec->offset)};
		for(int j=0; j<xRel->amount; j++){
			int type = ELF32_R_TYPE(eRel.rel->info);
			if(type == R_MIPS_16 || type == R_MIPS_REL32 || type > R_MIPS_LO16){
				printf("ERROR: Unsupported relocation type [%i]\n", type);
				return 1;
			}
			
			int sym_i = 1;
			for(int i=1; i<elf_sym_count; i++){
				if(i == ELF32_R_SYM(eRel.rel->info)) break;
				if(elf_symbols[i] != NULL) sym_i++;
			}
			
			*((XffRelocation*)(out + xRel->rels_off) + j) = (XffRelocation){
				.offset = eRel.rel->offset,
				.info = RelocAddrInfo(type, sym_i)
			};
			
			if(eSec->type == SHT_RELA){
			//	printf("RELA - S:%4i T:%1i  D:0x%08x V:0x%08x\n", sym_i, type, eRel.rela->data, *(uint*)INELF(elf_sections[eSec->info]->offset + eRel.rel->offset));
				XffSectionHeader* sec = xff_sections[eSec->info];
				switch(type){
					case R_MIPS_32:
						*(uint*)(out + sec->offset + eRel.rel->offset) = eRel.rela->addend;
						break;
					case R_MIPS_26:
						if(eRel.rela->addend != 0)
							printf("WARNING: Rela data for MIPS_26 not 0\n");
						//*(uint*)(out + sec->offset + eRel.rel->offset) |= eRel.rela->data;
						break;
					case R_MIPS_HI16:
						*(uint*)(out + sec->offset + eRel.rel->offset) |= (eRel.rela->addend >> 16) & 0xffff;
						ElfRelocationA tmprela;
						ElfRelocationA* next_rela = eRel.rela + 1;
						if(ELF32_R_TYPE(next_rela->info) != R_MIPS_LO16){
							while(ELF32_R_TYPE(next_rela->info) != R_MIPS_LO16)
								next_rela++;
							
							if(next_rela != eRel.rela+1){
								tmprela = *next_rela;
								
								ElfRelocationA* prev_rela = next_rela - 1;
								do{
									*next_rela = *prev_rela;
									next_rela = prev_rela;
									prev_rela--;
								} while(prev_rela != eRel.rela);
								
								*next_rela = tmprela;
							}
						}
						break;
					case R_MIPS_LO16:
						*(uint*)(out + sec->offset + eRel.rel->offset) |= eRel.rela->addend & 0xffff;
						break;
				}
			}
			else if(type == R_MIPS_HI16){
				ElfRelocation tmprel;
				ElfRelocation* next_rel = eRel.rel + 1;
				if(ELF32_R_TYPE(next_rel->info) != R_MIPS_LO16){
					while(ELF32_R_TYPE(next_rel->info) != R_MIPS_LO16)
						next_rel++;
					
					tmprel = *next_rel;
					
					ElfRelocation* prev_rel = next_rel - 1;
					do{
						*next_rel = *prev_rel;
						next_rel = prev_rel;
						prev_rel--;
					} while(prev_rel != eRel.rel);
					
					*next_rel = tmprel;
				}
			}
			
			*((XffRelocationAddend*)(out + xRel->addends_off) + j) = (XffRelocationAddend){
				.addend = *(uint*)(out + xff_sections[eSec->info]->offset + eRel.rel->offset)
			};
			
			if(eSec->type == SHT_REL) eRel.rel++;
			else eRel.rela++;
		}
	}
	
	if(!silent)
		printf("done\n\nWriting file...");
	
	
	// write file
	
	FILE* outf = fopen(outfilename, "wb");
	if(outf == NULL){
		printf("ERROR: Failed to create file \"%s\"\n", outfilename);
		return 1;
	}
	
	fwrite(out, 1, xff.file_size, outf);
	
	if(!silent)
		printf("done\n\nCleaning up...");
	
	// cleanup
	
	fclose(outf);
	free(out);
	for(int i=0; i<xff.rel_amount; i++){
		if(xff_relocations[i] != NULL)
			free(xff_relocations[i]);
	}
	for(int i=0; i<elf_sym_count; i++){
		if(xff_symbols[i] != NULL)
			free(xff_symbols[i]);
	}
	for(int i=0; i<elf->sec_entry_count; i++){
		if(xff_sections[i] != NULL)
			free(xff_sections[i]);
	}
	free(elf_relocations);
	free(xff_relocations);
	free(elf_symbols);
	free(xff_symbols);
	free(elf_sections);
	free(xff_sections);
	free(elf);
	
	if(!silent)
		printf("done\n");
	
	return 0;
}




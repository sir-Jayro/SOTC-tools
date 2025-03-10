#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>

#include "xff.h"
#include "elf.h"




void error(char* fmt, ...){
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	exit(1);
}



void segv_sig(int sig){
	error("\nERROR: Segment fault\n");
}



void* Malloc(size_t size){
	void* out = malloc(size);
	if(out == NULL)
		error("\nERROR: Memory error\n");
	return out;
}




int main(int argc, char** argv){
	signal(SIGSEGV, segv_sig);
	
// parse arguments ( TMP )
	char* infilename = argv[1];
	char* fnd = strchr(infilename, '.');
	int ofnl = strlen(infilename);
	if(fnd != NULL) ofnl = (fnd - infilename);
	char* outfilename = Malloc(ofnl + 5);
	strncpy(outfilename, infilename, ofnl);
	strcat(outfilename, ".elf");
	int silent = 0;
	
	
// check input file
	FILE* inf = fopen(infilename, "rb");
	if(inf == NULL)
		error("\nERROR: Failed to load file \"%s\"\n", infilename);
	Xff tmpxff;
	if(fread(&tmpxff, 1, sizeof(Xff), inf) != sizeof(Xff) || 
			(tmpxff.ident != XFF_IDENT && tmpxff.ident != XFF2_IDENT)){
INVAL_XFF:;
		fclose(inf);
		error("\nERROR: File \"%s\" not a valid XFF file\n", infilename);
	}
	fseek(inf, 0, SEEK_END);
	if(ftell(inf) != tmpxff.file_size) goto INVAL_XFF;
	
// load xff file
	Xff* xff = Malloc(tmpxff.file_size);
	fseek(inf, 0, SEEK_SET);
	if(fread(xff, 1, tmpxff.file_size, inf) != tmpxff.file_size)
		error("\nERROR: Error reading XFF file \"%s\"\n", infilename);
	fclose(inf);
	
// start building elf header
	ElfHeader elf = {
		.identification = { 0x7f, 0x45, 0x4c, 0x46, ELFCLASS32, ELFDATA2LSB, EV_CURRENT },
		.type = ET_REL,
		.machine = EM_MIPS,
		.version = EV_CURRENT,
		.flags = 0x20924001,
		.header_size = sizeof(ElfHeader),
		.sec_entry_size = sizeof(ElfSection),
		.sec_entry_count = xff->sec_amount
	};
	
#ifndef __x86_64__
	#define INXFF(o) ((int)xff + (o))
#else
	#define INXFF(o) ((long long)xff + (o))
#endif
	
	if(!silent)
		printf("Building ELF\n");
// build elf format
	int elf_size = sizeof(ElfHeader);
	int symstrtab_i = 0;
	int symtab_i = 0;
	int relsecnamelen = 0;
	
	XffSectionHeader* xffsecs = (XffSectionHeader*)INXFF(xff->secs_off);
	XffSymbolHeader* xffsyms = (XffSymbolHeader*)INXFF(xff->syms_off);
	XffRelocationHeader* xffrels = (XffRelocationHeader*)INXFF(xff->rels_off);
	uint* xffsecstroffs = (uint*)INXFF(xff->sec_name_offs_off);
	char* xffsecstrs = (char*)INXFF(xff->sec_names_off);
	uint* xffsymoffs = (uint*)INXFF(xff->sym_offs_off);
	
	
	for(int i=0; i<xff->rel_amount; i++){
		// TODO walk the array and find the next header with the same section as this one
		// then move it to be right under this one
		XffRelocationHeader* rel = xffrels + i;
		if(i + 1 < xff->rel_amount){
			XffRelocationHeader tmprel;
			XffRelocationHeader* nextrel = rel + 1;
			XffRelocationHeader* lastrel = xffrels + xff->rel_amount;
			
			while(nextrel != lastrel && nextrel->section != rel->section)
				nextrel++;
			
			if(nextrel != lastrel && nextrel != rel+1){
				tmprel = *nextrel;
				
				XffRelocationHeader* prevrel = nextrel - 1;
				do{
					*nextrel = *prevrel;
					nextrel = prevrel;
					prevrel--;
				} while(prevrel != rel);
				
				*nextrel = tmprel;
			}
		}
	}
	
	
	
	if(!silent)
		printf("  Reserving Section Data...");
	// reserve section data
	for(int i=1; i<xff->sec_amount; i++){
		//printf(".");
		XffSectionHeader* sec = xffsecs + i;
		switch(sec->type){
			case SEC_PROG:
				int align = sec->alignment - 1;
				if(align < 0) align = 0;
				elf_size = (elf_size + align) & ~align;
				sec->source = elf_size;
				elf_size += sec->size;
				break;
			case SEC_STRTAB:{
				char* name = xffsecstrs + xffsecstroffs[i];
				if(strcmp(name, ".shstrtab") == 0){
					elf.str_tab_entry_num = i;
					sec->offset = xff->sec_names_off;
				}
				else if(strcmp(name, ".strtab") == 0){
					symstrtab_i = i;
					sec->offset = xff->sym_names_off;
				}
				else{
					printf("\nWARNING: Unknown string table \"%s\"\n", name);
					sec->offset = 0;
					sec->size = 0;
					sec->type = SEC_NULL;
				}
				break;}
			case SEC_SYMTAB:
				symtab_i = i;
				break;
			case SEC_REL:{
				char* name = strchr(xffsecstrs + xffsecstroffs[i] + 1, '.');
				for(int j=0; j<xff->rel_amount; j++){
					XffRelocationHeader* rel = xffrels + j;
					if(rel->amount > 0 && strcmp(name, xffsecstrs + xffsecstroffs[rel->section]) == 0){
						rel->addends = i;
						sec->size = 0;
						if(sec->data == 0)
							sec->data = j+1;
						//break;
					}
				}
				break;}
		}
	}
	
	if(!silent)
		printf("done\n  Reserving Symbols...");
	// reserve symbols
	elf_size = (elf_size + (xffsecs[symtab_i].alignment-1)) & ~(xffsecs[symtab_i].alignment-1);
	xff->syms = elf_size;
	elf_size += xff->sym_amount * sizeof(ElfSymbol);
	
	if(!silent)
		printf("done\n  Reserving Symbol names...");
	// reserve symbol names
	xff->sym_names = elf_size;
	elf_size += xffsecs[symstrtab_i].size;
	
	if(!silent)
		printf("done\n  Reserving Relocations");
	// reserve relocations
	elf_size = (elf_size + 3) & ~3;
	for(int i=0; i<xff->rel_amount; i++){
		printf(".");
		XffRelocationHeader* rel = xffrels + i;
		if(rel->amount > 0){
			//printf("[%i %i %i] ", i, rel->section, (int)rel->data);
			if(rel->addends == 0){
				for(int j=1; j<xff->sec_amount; j++){
					XffSectionHeader* sec = xffsecs + j;
					//printf("[%i %i %i] ", i, j, (int)sec->pData);
					if(sec->type == SEC_REL && sec->data != 0 && xffrels[sec->data-1].section == rel->section){
						rel->addends = j;
						//printf("Found sec %i for rel %i\n", j, i);
						break;
					}
				}
				if(rel->addends == 0)
					elf.sec_entry_count++;
			}
			rel->rels = elf_size;
			if(rel->addends != 0){
				xffsecs[rel->addends].size += sizeof(ElfRelocation) * rel->amount;
				if(xffsecs[rel->addends].data-1 == i)
					xffsecs[rel->addends].offset = elf_size;
			}
			elf_size += sizeof(ElfRelocation) * rel->amount;
		}
	}
	
	if(!silent)
		printf("done\n  Reserving Section names...");
	// reserve section names
	xff->sec_names = elf_size;
	elf_size += xffsecs[elf.str_tab_entry_num].size;
	
	if(!silent)
		printf("done\n  Adding any missing Relocation Section names");
	// add the relocation section names
	for(int i=0; i<xff->rel_amount; i++){
		XffRelocationHeader* rel = xffrels + i;
		if(rel->amount > 0 && rel->addends == 0){
			if(!silent)
				printf(".");
			relsecnamelen += strlen(xffsecstrs + xffsecstroffs[rel->section]) + 5;
		}
	}
	elf_size += relsecnamelen;
	
	if(!silent)
		printf(" done\n  Reserving Sections...");
	// reserve sections
	elf_size = (elf_size + 3) & ~3;
	elf.sec_head_offset = elf_size;
	elf_size += sizeof(ElfSection) * xff->sec_amount;
	
	if(!silent)
		printf("done\n  Adding any missing Relocation Sections");
	// add relocation sections
	for(int i=0; i<xff->rel_amount; i++){
		XffRelocationHeader* rel = xffrels + i;
		if(rel->amount > 0 && rel->addends == 0){
			if(!silent)
				printf(".");
			elf_size += sizeof(ElfSection);
		}
	}
	
	
	if(!silent)
		printf(" done\ndone\n\nCopying XFF data to ELF\n  Copying ELF header...");
	// copy xff data to elf
	char* out = Malloc(elf_size);
	memset(out, 0, elf_size);
	memcpy(out, &elf, sizeof(ElfHeader));
	
	if(!silent)
		printf("done\n  Copying Section data");
	// copy section data
	for(int i=1; i<xff->sec_amount; i++){
		XffSectionHeader* sec = xffsecs + i;
		if(sec->type == SEC_PROG){
			if(!silent)
				printf(".");
//			printf("\n%i %08x - %08x %i", i, (int)sec->pSource, sec->offset, sec->size);
			memcpy(out + sec->source, (void*)INXFF(sec->offset), sec->size);
		}
	}
	
	if(!silent)
		printf("done\n  Copying Symbols...");
	// copy symbols
	for(int i=0; i<xff->sym_amount; i++){
		//printf(".");
		XffSymbolHeader* xSym = xffsyms + i;
		ElfSymbol* eSym = ((ElfSymbol*)(out + xff->syms)) + i;
		*eSym = (ElfSymbol){
			.name = xSym->name,
			.value = (xSym->section != 0) ? xffsymoffs[i] : 0,
			.size = (xSym->section != 0) ? xSym->size : 0,
			.info = xSym->info,
			.section = xSym->section
		};
	}
	
	if(!silent)
		printf("done\n  Copying Symbol names...");
	// copy symbol names
	memcpy(out + xff->sym_names, (char*)INXFF(xff->sym_names_off), xffsecs[symstrtab_i].size);
	
	if(!silent)
		printf("done\n  Copying Relocations");
	// copy relocations
	for(int i=0; i<xff->rel_amount; i++){
		XffRelocationHeader* xRel = xffrels + i;
		if(xRel->amount > 0){
			printf(".");
			ElfRelocation* eRels = (ElfRelocation*)(out + xRel->rels);
			for(int j=0; j<xRel->amount; j++)
				eRels[j] = *((ElfRelocation*)INXFF(xRel->rels_off) + j);
		}
	}
	
	if(!silent)
		printf("done\n  Copying Section names...");
	// copy section names
	memcpy(out + xff->sec_names, (char*)INXFF(xff->sec_names_off), xffsecs[elf.str_tab_entry_num].size);
	
	if(!silent)
		printf("done\n  Creating any missing Relocation Section names");
	// add the relocation section names
	char* name_i = out + xff->sec_names + xffsecs[elf.str_tab_entry_num].size;
	for(int i=0; i<xff->rel_amount; i++){
		XffRelocationHeader* rel = xffrels + i;
		if(rel->amount > 0 && rel->addends == 0){
			printf(".");
			strcpy(name_i, ".rel");
			strcat(name_i, xffsecstrs + xffsecstroffs[rel->section]);
			name_i += strlen(name_i) + 1;
		}
	}
	
	if(!silent)
		printf(" done\n  Copying Sections...");
	// copy sections
	for(int i=0; i<xff->sec_amount; i++){
		//printf(".");
		XffSectionHeader* xSec = xffsecs + i;
		ElfSection* eSec = (ElfSection*)(out + elf.sec_head_offset) + i;
		*eSec = (ElfSection){
			.name = xffsecstroffs[i],
			.type = xSec->type,
			.offset = xSec->source,
			.size = xSec->size,
			.align = xSec->alignment,
		};
		
		switch(xSec->type){
			case SEC_PROG:{
				char* name = xffsecstrs + xffsecstroffs[i];
				int istext = (strncmp(name, ".text", 5) == 0 ? SHF_EXECINSTR : 0);
				int isrodata = (strncmp(name, ".rodata", 7) == 0 ? SHF_STRINGS : 0);
				int canwrite = (!istext && !isrodata) ? SHF_WRITE : 0;
				eSec->flags = istext | isrodata | canwrite | SHF_ALLOC;
				break;}
			case SEC_NOBITS:
				eSec->flags = SHF_WRITE | SHF_ALLOC;
				break;
			case SEC_STRTAB:
				if(i == elf.str_tab_entry_num){
					eSec->size += relsecnamelen;
					eSec->offset = xff->sec_names;
				}
				else
					eSec->offset = xff->sym_names;
				break;
			case SEC_SYMTAB:
				eSec->link = symstrtab_i;
				eSec->info = xff->sec_sym_amount + 1;
				eSec->entry_size = sizeof(ElfSymbol);
				eSec->offset = xff->syms;
				break;
			case SEC_REL:{
				XffRelocationHeader* rel = xffrels + (xSec->data-1);
				eSec->flags = SHF_INFO_LINK;
				eSec->link = symtab_i;
				eSec->info = rel->section;
				//eSec->size = rel->amount * sizeof(ElfRelocation);
				eSec->entry_size = sizeof(ElfRelocation);
				eSec->offset = rel->rels;
				break;}
		}
	}
	
	if(!silent)
		printf("done\n  Creating any missing Relocation Sections");
	// add relocations sections
	int name_i_2 = xff->sec_names + xffsecs[elf.str_tab_entry_num].size;
	for(int i=0; i<xff->rel_amount; i++){
		XffRelocationHeader* rel = xffrels + i;
		if(rel->amount > 0 && rel->addends == 0){
			if(!silent)
				printf(".");
			ElfSection* eSec = (ElfSection*)(out + elf.sec_head_offset) + xff->sec_amount + i;
			*eSec = (ElfSection){
				.name = name_i_2 - xff->sec_names,
				.type = SHT_REL,
				.flags = SHF_INFO_LINK,
				.offset = rel->rels,
				.size = rel->amount * sizeof(ElfRelocation),
				.link = symtab_i,
				.info = rel->section,
				.align = 4,
				.entry_size = sizeof(ElfRelocation)
			};
			name_i_2 += strlen(out + name_i_2) + 1;
		}
	}
	
	if(!silent)
		printf("done\ndone\n\nWriting file to disk...");
	// write file
//*	
	FILE* outf = fopen(outfilename, "wb");
	if(outf == NULL){
		free(out);
		free(xff);
		free(outfilename);
		error("\nERROR: Failed to create file \"%s\"\n", outfilename);
	}
	if(!silent)
		printf(".");
	fwrite(out, 1, elf_size, outf);
	fclose(outf);
//*/
	
	if(!silent)
		printf("done\n\nCleaning up");
	// cleanup
	if(!silent)
		printf(".");
	free(out);
	if(!silent)
		printf(".");
	free(xff);
	if(!silent)
		printf(".");
	free(outfilename);
	
	if(!silent)
		printf("done\n");
	
	return 0;
}

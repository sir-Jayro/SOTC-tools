
/************************

	Simple ( and messy ) ELF file structures

************************/


#ifndef __ELF32_H__
#define __ELF32_H__


typedef unsigned int			uint;
typedef unsigned short			ushort;
typedef unsigned char			byte;
typedef uint					addr;



// E_IDENT
enum {
	EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3,
	EI_CLASS, EI_DATA, EI_VERSION, EI_PAD,
	EI_NIDENT=16
};

typedef struct{
	byte	identification[EI_NIDENT];	// The ELF indetification structure
	ushort	type;						// The type of ELF file this is (from enum table below)
	ushort	machine;					// The machine this ELF is for (from enum table below)
	uint	version;					// Always 1
	addr	entry;						// The physical address entry point for this file
	uint	prog_head_offset;			// The offset into the file for the Program Headers
	uint	sec_head_offset;			// The offset into the file of the Section Headers
	uint	flags;						// The flags for this ELF
	ushort	header_size;				// The size of this header
	ushort	prog_entry_size;			// The size of a Program Header
	ushort	prog_entry_count;			// The amount of Program Headers in this ELF
	ushort	sec_entry_size;				// The size of a Section Header
	ushort	sec_entry_count;			// The amount of Section Headers in this ELF
	ushort	str_tab_entry_num;			// The entry index into the Section Headers that references the String Table
} ElfHeader, Elf;

#define ELFMAG			0x464c457f

// EI_CLASS
enum { ELFCLASSNONE, ELFCLASS32, ELFCLASS64 };

// EI_DATA
enum { ELFDATANONE, ELFDATA2LSB, ELFDATA2MSB };

// E_MACHINE
enum {
	EM_NONE, EM_M32, EM_SPARC, EM_386, EM_68K, EM_88K,
	EM_860=7, EM_MIPS
};

// E_VERSION
enum { EV_NONE, EV_CURRENT };

// E_TYPE
enum {
	ET_NONE, ET_REL, ET_EXEC, ET_DYN, ET_CORE,
	ET_LOOS=0xfe00, ET_HIOS=0xfeff,
	ET_LOPROC=0xff00, ET_HIPROC=0xffff
};





typedef struct{
	uint	name;
	uint	type;
	uint	flags;
	addr	addr;
	uint	offset;
	uint	size;
	uint	link;
	uint	info;
	uint	align;
	uint	entry_size;
} ElfSection;

// Special Section Indexes
enum {
	SHN_UNDEF, SHN_LORESERVE=0xff00, SHN_LOPROC=0xff00,
	SHN_HIPROC=0xff1f, SHN_ABS=0xfff1, SHN_COMMON,
	SHN_HIRESERVE=0xffff
};

// SH_TYPE
enum {
	SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA,
	SHT_HASH, SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS, SHT_REL,
	SHT_SHLIB, SHT_DYNSYM, SHT_LOPROC=0x70000000,
	SHT_HIPROC=0x7fffffff, SHT_LOUSER=0x80000000,
	SHT_HIUSER=0xffffffff
};

// SH_FLAGS
enum {
	SHF_WRITE=0x1, SHF_ALLOC=0x2, SHF_EXECINSTR=0x4, SHF_MERGE=0x10,
	SHF_STRINGS=0x20, SHF_INFO_LINK=0x40, SHF_LINK_ORDER=0x80, SHF_MASKPROC=0xf0000000
};







typedef struct{
	uint	name;
	uint	value;
	uint	size;
	byte	info;
	byte	other;
	ushort	section;
} ElfSymbol;

#define ELF32_ST_BIND(i)	((i)>>4)
#define ELF32_ST_TYPE(i)	((i)&0xf)
#define ELF32_ST_INFO(b,t)	(((b)<<4)+((t)&0xf))

// ELF32_ST_BIND
enum {
	STB_LOCAL, STB_GLOBAL, STB_WEAK,
	STB_LOPROC=13, STB_HIPROC=15
};

// ELF32_ST_TYPE
enum {
	STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION, STT_FILE,
	STT_LOPROC=13, STT_HIPROC=15
};





typedef struct{
	union{
		addr	address;
		uint	offset;
	};
	uint	info;
} ElfRelocation;

typedef struct{
	union{
		addr	address;
		uint	offset;
	};
	uint	info;
	uint	addend;
} ElfRelocationA;

typedef union{ ElfRelocation* rel; ElfRelocationA* rela; } pElfRelocation;

#define ELF32_R_SYM(i)		((i)>>8)
#define ELF32_R_TYPE(i)		((byte)(i))
#define ELF32_R_INFO(s,t)	(((s)<<8)+(byte)(t))

// Relocation Types
enum {
	R_386_NONE, R_386_32, R_386_PC32, R_386_GOT32, R_386_PLT32,
	R_386_COPY, R_386_GLOB_DAT, R_386_JMP_SLOT, R_386_RELATIVE,
	R_386_GOTOFF, R_386_GOTPC, R_386_16=20,
	
	R_MIPS_NONE = 0, R_MIPS_16, R_MIPS_32, R_MIPS_REL32, R_MIPS_26,
	R_MIPS_HI16, R_MIPS_LO16, R_MIPS_GPREL16, R_MIPS_LITERAL,
	R_MIPS_GOT16, R_MIPS_PC16, R_MIPS_CALL16, R_MIPS_GPREL32,
	R_MIPS_GOTHI16, R_MIPS_GOTLO16, R_MIPS_CALLHI16, R_MIPS_CALLLO16
};






typedef struct{
	uint	type;
	uint	offset;
	addr	vaddr;
	addr	paddr;
	uint	filesz;
	uint	memsz;
	uint	flags;
	uint	align;
} ElfProgram;







#endif

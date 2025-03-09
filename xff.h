
/**********************************************


	Xff File Structures


**********************************************/


#ifndef XFF
#define XFF


// The file identifiers
#define XFF_IDENT	0x00666678		// "xff\0"
#define XFF2_IDENT	0x32666678		// "xff2"



#ifdef __cplusplus
extern "C" {
#endif


// Common typedefs
typedef unsigned char	byte;
typedef unsigned short	ushort;
typedef unsigned int	uint;
typedef uint			addr;		// All pointers are 32 bit. This typedef allows for 64 bit compilation


// Section Types
enum XFF_SEC_TYPE {
	SEC_NULL,						// No type
	SEC_PROG,						// Program bits. Aka program code and data
	SEC_SYMTAB,						// Symbol table
	SEC_STRTAB,						// String Table
	SEC_RELA,						// Relocation with Addends
	SEC_NOBITS	= 8,				// No bits. Aka a block of program data that's allocated and cleared to 0 at runtime ( .bss )
	SEC_REL							// Relocations
};


// Section Allocation Type
// **** These are only used after the file has been loaded in game ****
enum XFF_SEC_ALLOC_TYPE {
	ALOC_NORMAL,					// Section is aligned properly in place
	ALOC_OUT_OF_ALIGN,				// The Section was out of alignment when loaded and has been copied to an aligned address
	ALOC_ALLOC_FLAG					// The Section needed to be allocated ( used for SEC_NOBITS )
};


// Section Header structure
typedef struct {
// NOTE( "data" and "source" should be the same. Unless the section was out of alignment when loaded, then "source" will point to the data in the file and "data" will point to the aligned data copy )
	addr	data;					// TYPE( void* ), USE( after load ) - A pointer to the section's data in memory
	addr	source;					// TYPE( void* ), USE( after load ) - A pointer to the section's data in memory before alignment
	uint	size;					// The size of the section's data
	uint	alignment;				// The alignment required for the section
	uint	type;					// TYPE( XFF_SEC_TYPE ) - The type of the section
	uint	alloc;					// Set to 1 if this section requires allocation ( for SEC_NOBITS )
	uint	alloc_type;				// TYPE( XFF_SEC_ALLOC_TYPE ), USE( after load ) - The type of allocation this section needed when loaded
	uint	offset;					// The offset into the file this section resides
} XffSectionHeader;


// Symbol Types
enum XFF_SYM_TYPE {
	SYM_NOTYPE,						// No type
	SYM_OBJECT,						// Object / data
	SYM_FUNC,						// Function
	SYM_SEC							// Section
};


// Symbol Binds
enum XFF_SYM_BIND {
	SYM_LOCAL,
	SYM_GLOBAL
};


// Special Symbol Section Types
enum XFF_SYM_SEC {
	SYMSEC_UNDEF,					// Undefined Section. Typically used for external symbols
	SYMSEC_ABS			= 0xfff1,	// Absolute. The symbol offset is the address
	SYMSEC_COMMON,					// Sometimes used for SEC_NOBITS data
};


#define SymbolType( i )		( (i) & 0xf )
#define SymbolBind( i )		( ( (i) >> 4 ) & 0xf )
#define SymbolInfo( t, b )	( ( (t) & 0xf ) | ( (b) << 4 ) )


// Symbol Header structure
typedef struct {
	uint	name;					// The offset into the symbol STRTAB (string table) of the symbol name
	addr	address;				// TYPE( void* ), USE( after load ) - The address in memory of the symbol data
	uint	size;					// The size of the symbol data
	byte	info;					// Extra symbol information ( symbol type and binding )
	byte	in_use;					// USE( after load ) - Set to 1 if the symbol is used by an external module
	ushort	section;				// The section the symbol resides in
} XffSymbolHeader;


// Relocation type
enum XFF_REL_TYPE {
	REL_NONE,						// No relocation
	REL_PTR		= 2,				// A 4 byte pointer
	REL_ADDR	= 4,				// A 26 bit jump/call address
	REL_HIGH,						// The high 16 bytes
	REL_LOW							// The low 16 bytes
};

#define RelocAddrType( i )		( (i) & 0xff )
#define RelocAddrSym( i )		( (i) >> 8 )
#define RelocAddrInfo( t, s )	( ( (s) << 8 ) | ( (t) & 0xff ) )


// Relocation structure
typedef struct {
	uint	offset;					// The offset in the section the relocation will apply
	uint	info;					// Extra relocation information ( relocation type and symbol )
} XffRelocation;


// Relocation Addend structure
typedef struct {
	uint	value;					// The data/instruction + offset to add the symbol address to
	int		_;						// UNUSED. Always 0
} XffRelocationAddend;


// Relocation Header structure
typedef struct {
	uint	type;					// The type of relocation header ( SEC_REL or SEC_RELA )
	uint	amount;					// The amount of relocations
	uint	section;				// The section to apply the relocations to
	addr	rels;					// TYPE( XffRelocation* ), USE( after load ) - A pointer to the relocations array
	addr	addends;				// TYPE( XffRelocationAddend* ), USE( after load ) - A pointer to the addends array
	uint	rels_offset;			// The offset in the file of the relocations array
	uint	addends_offset;			// The offset in the file of the addends array
} XffRelocationHeader;


// The main Xff file Header structure
typedef struct {
	uint	ident;					// The file identifier
	addr	data_buf;				// TYPE( void* ), USE( after load ) - A pointer to a buffer used after loading. Can hold different things, typically strings and hashed symbol name structures
	uint	next_offset;			// The offset in memory of the next Xff file. Or 0 if none
	uint	sec_sym_amount;			// The amount of symbols at the start of the SYMTAB ( symbol table ) that correspond to sections
	addr	entry;					// TYPE( void* ), USE( after load ) - The entry point function address or a pointer to the main data structure of the file
	uint	file_size;				// The size of the file in bytes
	addr	file_end;				// TYPE( void* ), USE( after load ) - A pointer to the address directly after the file in memory
	uint	external_sym_amount;	// The amount of symbols that are external ( not from this file )
	addr	externals;				// TYPE( uint* ), USE( after load ) - A pointer to the external symbol index array
	uint	sym_amount;				// The amount of symbols
	addr	syms;					// TYPE( XffSymbolHeader* ), USE( after load ) - A pointer to the SYMTAB
	addr	sym_names;				// TYPE( char* ), USE( after load ) - A pointer to the STRTAB for the SYMTAB
	addr	secs;					// TYPE( XffSectionHeader* ), USE( after load ) - A pointer to the SECTAB ( section table )
	addr	sym_offs;				// TYPE( uint* ), USE( after load ) - A pointer to the symbol offset array
	uint	rel_amount;				// The amount of relocation headers
	addr	rels;					// TYPE( XffRelocationHeader* ), USE( after load ) - A pointer to the relocation header array
	uint	sec_amount;				// The amount of sections
	addr	sec_name_offs;			// TYPE( uint* ), USE( after load ) - A pointer to the section name offset array
	addr	sec_names;				// TYPE( char* ), USE( after load ) - A pointer to the STRTAB for the SECTAB
	
	uint	entry_off;				// The offset in the first section of the entry point or main data structure
	uint	externals_off;			// The offset in the file of the external symbol index array
	uint	syms_off;				// The offset in the file of the SYMTAB
	uint	sym_names_off;			// The offset in the file of the STRTAB for the SYMTAB
	uint	sec_off;				// The offset in the file of the SECTAB
	uint	sym_offs_off;			// The offset in the file of the symbol offset array
	uint	rels_off;				// The offset in the file of the relocation header array
	uint	sec_name_offs_off;		// The offset in the file of the section name offset array
	uint	sec_names_off;			// The offset in the file of the STRTAB of the SECTAB
} XffHeader;

typedef XffHeader	Xff;



/**********************************************
	Typical layout of a Xff file

	XffHeader
	section_names_offsets
	XffSectionHeaders
	symbol_offsets
	XffRelocationHeaders
	external_symbol_indices
	section_names
	-
	section data
	-
	XffSymbolHeaders
	symbol_names
	relocations and relocation_addends
	
**********************************************/



#ifdef __cplusplus
}
#endif


#endif

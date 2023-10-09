#ifndef _LIBDEX_DEXCLASS
#define _LIBDEX_DEXCLASS

#include "DexFile.h"
#include "Leb128.h"

typedef struct DexClassDataHeader {
    u4 staticFieldsSize;
    u4 instanceFieldsSize;
    u4 directMethodsSize;
    u4 virtualMethodsSize;
} DexClassDataHeader;

typedef struct DexField {
    u4 fieldIdx; 
    u4 accessFlags;
} DexField;

typedef struct DexMethod {
    u4 methodIdx; 
    u4 accessFlags;
    u4 codeOff; 
} DexMethod;

typedef struct DexClassData {
    DexClassDataHeader header;
    DexField *staticFields;
    DexField *instanceFields;
    DexMethod *directMethods;
    DexMethod *virtualMethods;
} DexClassData;




void dexReadClassDataHeader(const u1 **pData, DexClassDataHeader *pHeader);

#endif

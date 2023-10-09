#include "pch.h"
#include"DexClass.h"

/* Read the header of a class_data_item without verification. This
 * updates the given data pointer to point past the end of the read
 * data. */

void dexReadClassDataHeader(const u1 **pData, DexClassDataHeader *pHeader) {
    pHeader->staticFieldsSize = readUnsignedLeb128(pData);
    pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
    pHeader->directMethodsSize = readUnsignedLeb128(pData);
    pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
}
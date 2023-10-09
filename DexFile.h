#ifndef LIBDEX_DEXFILE_H_
#define LIBDEX_DEXFILE_H_

#ifndef LOG_TAG
# define LOG_TAG "libdex"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#if defined(VERY_VERBOSE_LOG)
# define LOGVV      ALOGV
# define IF_LOGVV() IF_ALOGV()
#else
# define LOGVV(...) ((void)0)
# define IF_LOGVV() if (false)
#endif

typedef uint8_t             u1;
typedef uint16_t            u2;
typedef uint32_t            u4;
typedef uint64_t            u8;
typedef int8_t              s1;
typedef int16_t             s2;
typedef int32_t             s4;
typedef int64_t             s8;


#ifndef _DEX_GEN_INLINES                  
# define extern __inline__
#else
# define DEX_INLINE
#endif

#define DEX_MAGIC       "dex\n"

#define DEX_MAGIC_VERS_37  "037\0"

#define DEX_MAGIC_VERS_38  "038\0"

#define DEX_MAGIC_VERS_39  "039\0"

#define DEX_MAGIC_VERS  "036\0"

#define DEX_MAGIC_VERS_API_13  "035\0"

#define DEX_OPT_MAGIC   "dey\n"
#define DEX_OPT_MAGIC_VERS  "036\0"

#define DEX_DEP_MAGIC   "deps"

enum {
    kSHA1DigestLen = 20,
    kSHA1DigestOutputLen = kSHA1DigestLen * 2 + 1
};

enum {
    kDexEndianConstant = 0x12345678,        
    kDexNoIndex = 0xffffffff,                 
};

enum PrimitiveType {
    PRIM_NOT = 0,                 
    PRIM_VOID = 1,
    PRIM_BOOLEAN = 2,
    PRIM_BYTE = 3,
    PRIM_SHORT = 4,
    PRIM_CHAR = 5,
    PRIM_INT = 6,
    PRIM_LONG = 7,
    PRIM_FLOAT = 8,
    PRIM_DOUBLE = 9,
};

enum {
    ACC_PUBLIC = 0x00000001,           
    ACC_PRIVATE = 0x00000002,          
    ACC_PROTECTED = 0x00000004,          
    ACC_STATIC = 0x00000008,          
    ACC_FINAL = 0x00000010,           
    ACC_SYNCHRONIZED = 0x00000020,            
    ACC_SUPER = 0x00000020,            
    ACC_VOLATILE = 0x00000040,        
    ACC_BRIDGE = 0x00000040,         
    ACC_TRANSIENT = 0x00000080,        
    ACC_VARARGS = 0x00000080,         
    ACC_NATIVE = 0x00000100,        
    ACC_INTERFACE = 0x00000200,         
    ACC_ABSTRACT = 0x00000400,          
    ACC_STRICT = 0x00000800,        
    ACC_SYNTHETIC = 0x00001000,          
    ACC_ANNOTATION = 0x00002000,          
    ACC_ENUM = 0x00004000,           
    ACC_CONSTRUCTOR = 0x00010000,          
    ACC_DECLARED_SYNCHRONIZED =
        0x00020000,          
    ACC_CLASS_MASK =
        (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT
         | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM),
    ACC_INNER_CLASS_MASK =
        (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC),
    ACC_FIELD_MASK =
        (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
         | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM),
    ACC_METHOD_MASK =
        (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
         | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
         | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
         | ACC_DECLARED_SYNCHRONIZED),
};

enum {
    kDexVisibilityBuild = 0x00,        
    kDexVisibilityRuntime = 0x01,
    kDexVisibilitySystem = 0x02,

    kDexAnnotationByte = 0x00,
    kDexAnnotationShort = 0x02,
    kDexAnnotationChar = 0x03,
    kDexAnnotationInt = 0x04,
    kDexAnnotationLong = 0x06,
    kDexAnnotationFloat = 0x10,
    kDexAnnotationDouble = 0x11,
    kDexAnnotationMethodType = 0x15,
    kDexAnnotationMethodHandle = 0x16,
    kDexAnnotationString = 0x17,
    kDexAnnotationType = 0x18,
    kDexAnnotationField = 0x19,
    kDexAnnotationMethod = 0x1a,
    kDexAnnotationEnum = 0x1b,
    kDexAnnotationArray = 0x1c,
    kDexAnnotationAnnotation = 0x1d,
    kDexAnnotationNull = 0x1e,
    kDexAnnotationBoolean = 0x1f,

    kDexAnnotationValueTypeMask = 0x1f,         
    kDexAnnotationValueArgShift = 5,
};

enum {
    kDexTypeHeaderItem = 0x0000,
    kDexTypeStringIdItem = 0x0001,
    kDexTypeTypeIdItem = 0x0002,
    kDexTypeProtoIdItem = 0x0003,
    kDexTypeFieldIdItem = 0x0004,
    kDexTypeMethodIdItem = 0x0005,
    kDexTypeClassDefItem = 0x0006,
    kDexTypeCallSiteIdItem = 0x0007,
    kDexTypeMethodHandleItem = 0x0008,
    kDexTypeMapList = 0x1000,
    kDexTypeTypeList = 0x1001,
    kDexTypeAnnotationSetRefList = 0x1002,
    kDexTypeAnnotationSetItem = 0x1003,
    kDexTypeClassDataItem = 0x2000,
    kDexTypeCodeItem = 0x2001,
    kDexTypeStringDataItem = 0x2002,
    kDexTypeDebugInfoItem = 0x2003,
    kDexTypeAnnotationItem = 0x2004,
    kDexTypeEncodedArrayItem = 0x2005,
    kDexTypeAnnotationsDirectoryItem = 0x2006,
};

enum {
    kDexChunkClassLookup = 0x434c4b50,     
    kDexChunkRegisterMaps = 0x524d4150,     

    kDexChunkEnd = 0x41454e44,     
};

enum {
    DBG_END_SEQUENCE = 0x00,
    DBG_ADVANCE_PC = 0x01,
    DBG_ADVANCE_LINE = 0x02,
    DBG_START_LOCAL = 0x03,
    DBG_START_LOCAL_EXTENDED = 0x04,
    DBG_END_LOCAL = 0x05,
    DBG_RESTART_LOCAL = 0x06,
    DBG_SET_PROLOGUE_END = 0x07,
    DBG_SET_EPILOGUE_BEGIN = 0x08,
    DBG_SET_FILE = 0x09,
    DBG_FIRST_SPECIAL = 0x0a,
    DBG_LINE_BASE = -4,
    DBG_LINE_RANGE = 15,
};

struct DexHeader {
    u1  magic[8];                 
    u4  checksum;       
    u1  signature[kSHA1DigestLen];       
    u4  fileSize;       
    u4  headerSize;     
    u4  endianTag;      
    u4  linkSize;       
    u4  linkOff;        
    u4  mapOff;          
    u4  stringIdsSize;      
    u4  stringIdsOff;       
    u4  typeIdsSize;        
    u4  typeIdsOff;         
    u4  protoIdsSize;       
    u4  protoIdsOff;        
    u4  fieldIdsSize;       
    u4  fieldIdsOff;        
    u4  methodIdsSize;      
    u4  methodIdsOff;       
    u4  classDefsSize;      
    u4  classDefsOff;       
    u4  dataSize;           
    u4  dataOff;            
};

struct DexMapItem {
    u2 type;                    
    u2 unused;
    u4 size;                      
    u4 offset;                    
};

struct DexMapList {
    u4  size;                    
    DexMapItem list[1];       
};

struct DexStringId {
    u4 stringDataOff;           
};

struct DexTypeId {
    u4  descriptorIdx;        
};

struct DexFieldId {
    u2  classIdx;             
    u2  typeIdx;              
    u4  nameIdx;              
};

struct DexMethodId {
    u2  classIdx;             
    u2  protoIdx;             
    u4  nameIdx;              
};

struct DexProtoId {
    u4  shortyIdx;            
    u4  returnTypeIdx;        
    u4  parametersOff;         
};

struct DexClassDef {
    u4  classIdx;             
    u4  accessFlags;          
    u4  superclassIdx;        
    u4  interfacesOff;        
    u4  sourceFileIdx;        
    u4  annotationsOff;       
    u4  classDataOff;         
    u4  staticValuesOff;      
};

struct DexCallSiteId {
    u4  callSiteOff;             
};

enum MethodHandleType {
    STATIC_PUT = 0x00,
    STATIC_GET = 0x01,
    INSTANCE_PUT = 0x02,
    INSTANCE_GET = 0x03,
    INVOKE_STATIC = 0x04,
    INVOKE_INSTANCE = 0x05,
    INVOKE_CONSTRUCTOR = 0x06,
    INVOKE_DIRECT = 0x07,
    INVOKE_INTERFACE = 0x08
};

struct DexMethodHandleItem {
    u2 methodHandleType;         
    u2 reserved1;                
    u2 fieldOrMethodIdx;           
    u2 reserved2;                
};

struct DexTypeItem {
    u2  typeIdx;                
};

struct DexTypeList {
    u4  size;                    
    DexTypeItem list[1];      
};

struct DexCode {
    u2  registersSize;    
    u2  insSize;          
    u2  outsSize;         
    u2  triesSize;        
    u4  debugInfoOff;         
    u4  insnsSize;            
    u2  insns[1];              
};

struct DexTry {
    u4  startAddr;                 
    u2  insnCount;                 
    u2  handlerOff;                 
};

struct DexLink {
    u1  bleargh;
};


struct DexAnnotationsDirectoryItem {
    u4  classAnnotationsOff;      
    u4  fieldsSize;               
    u4  methodsSize;              
    u4  parametersSize;           
};

struct DexFieldAnnotationsItem {
    u4  fieldIdx;
    u4  annotationsOff;                 
};

struct DexMethodAnnotationsItem {
    u4  methodIdx;
    u4  annotationsOff;                 
};

struct DexParameterAnnotationsItem {
    u4  methodIdx;
    u4  annotationsOff;                 
};

struct DexAnnotationSetRefItem {
    u4  annotationsOff;                 
};

struct DexAnnotationSetRefList {
    u4  size;
    DexAnnotationSetRefItem list[1];
};

struct DexAnnotationSetItem {
    u4  size;
    u4  entries[1];                     
};

struct DexAnnotationItem {
    u1  visibility;
    u1  annotation[1];                   
};

struct DexEncodedArray {
    u1  array[1];                        
};

struct DexClassLookup {
    int     size;                           
    int     numEntries;                        
    struct {
        u4      classDescriptorHash;        
        int     classDescriptorOffset;        
        int     classDefOffset;               
    } table[1];
};

struct DexOptHeader {
    u1  magic[8];               

    u4  dexOffset;                
    u4  dexLength;
    u4  depsOffset;                
    u4  depsLength;
    u4  optOffset;                 
    u4  optLength;

    u4  flags;                  
    u4  checksum;                

};

#define DEX_OPT_FLAG_BIG            (1<<1)      

#define DEX_INTERFACE_CACHE_SIZE    128           

struct DexFile {
    DexHeader    *pHeader;         
    DexStringId  *pStringIds;     
    DexTypeId    *pTypeIds;       
    DexFieldId   *pFieldIds;      
    DexMethodId  *pMethodIds;      
    DexProtoId   *pProtoIds;      
    DexClassDef  *pClassDefs;     
    DexLink      *pLinkData;       

    const DexClassLookup *pClassLookup;
    const void         *pRegisterMapPool;        

    const u1           *baseAddr;

    int                 overhead;

};


#endif   

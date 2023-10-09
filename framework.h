#pragma once

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN               
#endif

#include "targetver.h"

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS         

#define _AFX_ALL_WARNINGS

#include <afxwin.h>           
#include <afxext.h>           



#ifndef _AFX_NO_OLE_SUPPORT
#include <afxdtctl.h>                 
#endif
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>                 
#endif  

#include <afxcontrolbars.h>       


#ifdef _UNICODE
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif



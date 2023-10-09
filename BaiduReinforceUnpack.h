
#pragma once

#ifndef __AFXWIN_H__
	#error "Include 'pch.h' before including this file to generate the PCH"
#endif

#include "resource.h"	

class CBaiduReinforceUnpackApp : public CWinApp
{
public:
	CBaiduReinforceUnpackApp();

public:
	virtual BOOL InitInstance();


	DECLARE_MESSAGE_MAP()
};

extern CBaiduReinforceUnpackApp theApp;

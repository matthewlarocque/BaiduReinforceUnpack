
#pragma once


class CBaiduReinforceUnpackDlg : public CDialogEx
{
public:
	CBaiduReinforceUnpackDlg(CWnd* pParent = nullptr);	 

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_BAIDUREINFORCEUNPACK_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	  


protected:
	HICON m_hIcon;

	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedMfcbutton1();
	afx_msg void OnEnChangeEdit1();
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnBnClickedButton1();
};

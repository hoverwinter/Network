
// RouterDlg.h : 头文件
//

#pragma once


// CRouterDlg 对话框
class CRouterDlg : public CDialogEx
{
// 构造
public:
	CRouterDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_ROUTER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton3();
	afx_msg void OnStartClickedBtn();
	afx_msg void OnStopClickedBtn();
	afx_msg void OnAddClickedRouterBtn();
	afx_msg void OnDeleteClickedRouterBtn();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnDestroy();
	CListBox Logger;
	CListBox m_RouteTable;
	CIPAddressCtrl m_Destination;
	CIPAddressCtrl m_NextHop;
	CIPAddressCtrl m_Mask;
	CListBox m_MacIP;
};

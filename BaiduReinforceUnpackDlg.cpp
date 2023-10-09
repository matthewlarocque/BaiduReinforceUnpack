#include "pch.h"
#include "framework.h"
#include "BaiduReinforceUnpack.h"
#include "BaiduReinforceUnpackDlg.h"
#include "afxdialogex.h"

#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <iomanip>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <numeric>
#include <utility>
#include <unordered_set>

#include <afxtaskdialog.h>

#include "DexFile.h"
#include "DexClass.h"
#include "InstrUtils.h"

unsigned char op_replace_array[0x100];
InstructionWidth instrWidth[0x100];


#pragma pack(1)
struct append_data_header {
    int index;
    int size_1;
    int offset_1;
    int size_2;
};


struct method_info_header {
    char unknown_1[6];
    int unknown_2;
    int string_num;
    int string_offset;
    int unknown_3;
    int unknown_4;
    int method_num;
    int method_code_item_offset;
    int op_replace_offset;
};


struct baidu_code_item {
    int unknown_1;
    short unknown_2;
    int unknown_3;
    short unknown_4;
    short outs_size;
    short ins_size;
    short registers_size;
    short s_idx;
    short insns_size;
};



std::unique_ptr<unsigned char[]> read_file(std::string& str_file_path, int& file_len) {
    std::ifstream ifs(str_file_path, std::ifstream::binary);
    ifs.seekg(0, ifs.end);
    file_len = static_cast<int>(ifs.tellg());
    unsigned char* np_buf = new unsigned char[file_len];
    ifs.seekg(0, ifs.beg);
    ifs.read(reinterpret_cast<char*>(np_buf), file_len);
    std::unique_ptr<unsigned char[]> up_buf(np_buf);
    ifs.close();
    AfxMessageBox(L"Sure!");
    return up_buf;
}

// Replace command with the command replacement table in the additional data 3
void fill_op(unsigned char* op_replace_ptr) {
    for (int i = 0; i < 0x100; i++)
        op_replace_array[op_replace_ptr[i]] = i;
}

// Constructing a DexCode list
std::vector<std::pair<int, std::unique_ptr<char[]>>>  parse_append_data(unsigned char* dex_buf, int dex_len) {
    std::vector<std::pair<int, std::unique_ptr<char[]>>> v_dex_code;// 'first' is the start offset of the current code
    append_data_header* append_data_header_ptr = reinterpret_cast<append_data_header*>(dex_buf + dex_len - 0x118);
    unsigned char* method_info_ptr = reinterpret_cast<unsigned char*>(append_data_header_ptr) - append_data_header_ptr->size_2;
    method_info_header* method_info_header_ptr = reinterpret_cast<method_info_header*>(method_info_ptr);
    fill_op(method_info_ptr + method_info_header_ptr->op_replace_offset);// First construct the array for replacing instructions using the instruction replacement table in Additional Data 3
    dexCreateInstrWidthTable(instrWidth);// Generate an array with the width of each instruction
    baidu_code_item* baidu_code_item_ptr = reinterpret_cast<baidu_code_item*>(method_info_ptr + method_info_header_ptr->method_code_item_offset);
    auto dex_code_len = 0;
    for (int method_index = 0; method_index < method_info_header_ptr->method_num; method_index++) { // Iterate through the methods in Additional Data 3
        unsigned short* insns = reinterpret_cast<unsigned short*>(baidu_code_item_ptr + 1);
        int width, insns_index = 0;
        for (; insns_index < baidu_code_item_ptr->insns_size; insns_index += width) { // Iterate through each instruction
            width = dexGetInstrOrTableWidthAbs(instrWidth, insns + insns_index, op_replace_array);// While calculating each instruction, the instruction will be replaced back through the replacement table
        }
        int tries_size = insns[insns_index];
        int tries_len = insns[insns_index + 1];
        unsigned char* tries = reinterpret_cast<unsigned char*>(insns + insns_index + 2);
        int pad_len = baidu_code_item_ptr->insns_size % 2 ? 1 : 0;// The instructions in the additional data are not padded and aligned, so you need to calculate them yourself
        auto code_len = 0x10 + (baidu_code_item_ptr->insns_size + pad_len) * 2 + tries_len;
        code_len = (code_len + 3) / 4 * 4;// The added codes are stored one by one, and each code length is 4-byte aligned for ease of calculation
        char* np_dex_code = new char[code_len];
        v_dex_code.push_back(std::make_pair(dex_code_len, std::unique_ptr<char[]>(np_dex_code)));
        dex_code_len += code_len;
        DexCode* code_ptr = reinterpret_cast<DexCode*>(np_dex_code);
        code_ptr->registersSize = baidu_code_item_ptr->registers_size;
        code_ptr->insSize = baidu_code_item_ptr->ins_size;
        code_ptr->outsSize = baidu_code_item_ptr->outs_size;
        code_ptr->triesSize = tries_size;
        code_ptr->debugInfoOff = 0;
        code_ptr->insnsSize = baidu_code_item_ptr->insns_size;
        auto tries_ptr = std::copy_n(insns, baidu_code_item_ptr->insns_size, &code_ptr->insns[0]);// Copy instructions
        if (pad_len)// align instructions' lengths
            *(tries_ptr++) = 0;
        std::copy_n(tries, tries_len, reinterpret_cast<unsigned char*>(tries_ptr)); // Abnormal related data
        baidu_code_item_ptr = reinterpret_cast<baidu_code_item*>(tries + tries_len); // next method
    }
    v_dex_code.push_back(std::make_pair(dex_code_len, nullptr));
    return v_dex_code;
}

void parse_class_methods(unsigned char* dex_buf, std::ostream& os = std::cout) {
    DexHeader* dex_header_ptr = reinterpret_cast<DexHeader*>(dex_buf);
    DexStringId* string_ids = reinterpret_cast<DexStringId*>(dex_buf + dex_header_ptr->stringIdsOff);
    DexTypeId* type_ids = reinterpret_cast<DexTypeId*>(dex_buf + dex_header_ptr->typeIdsOff);
    DexProtoId* proto_ids = reinterpret_cast<DexProtoId*>(dex_buf + dex_header_ptr->protoIdsOff);
    DexMethodId* method_ids = reinterpret_cast<DexMethodId*>(dex_buf + dex_header_ptr->methodIdsOff);
    DexClassDef* class_defs = reinterpret_cast<DexClassDef*>(dex_buf + dex_header_ptr->classDefsOff);
    auto class_defs_size = dex_header_ptr->classDefsSize;
    for (u4 class_index = 0; class_index < class_defs_size; class_index++) {
        auto class_name_ptr = dex_buf + string_ids[type_ids[class_defs[class_index].classIdx].descriptorIdx].stringDataOff;
        while (*class_name_ptr++ & 0x80);
        os << std::dec << std::setfill(' ')
            << std::setw(6) << class_index << ' ' << class_name_ptr << std::endl;
        auto class_data_off = class_defs[class_index].classDataOff;
        if (class_data_off == 0)
            continue;
        unsigned char* class_data_ptr = dex_buf + class_data_off;
        DexClassDataHeader st_class_data_header;
        dexReadClassDataHeader(const_cast<const u1**>(&class_data_ptr), &st_class_data_header);
        for (size_t i = 0; i < st_class_data_header.staticFieldsSize + st_class_data_header.instanceFieldsSize; i++) {
            readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
            readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
        }
        auto parse_methods_array = [&](std::string type, u4 methods_size)->void {
            os << std::hex << std::setfill('0');
            auto method_id = 0;
            for (size_t methods_index = 0; methods_index < methods_size; methods_index++) {
                method_id += readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
                readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
                auto code_off = readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
                os << "\t\t" << type << "_method_id:0x" << std::setw(8) << method_id << ", code_off:0x" << std::setw(8) << code_off << " | ";
                DexMethodId* method_id_ptr = method_ids + method_id;
                auto method_name_ptr = dex_buf + string_ids[method_id_ptr->nameIdx].stringDataOff;
                while (*method_name_ptr++ & 0x80);
                os << method_name_ptr << "(";
                DexProtoId* proto_id_ptr = proto_ids + method_id_ptr->protoIdx;
                if (proto_id_ptr->parametersOff != 0) {
                    DexTypeList* type_list_ptr = reinterpret_cast<DexTypeList*>(dex_buf + proto_id_ptr->parametersOff);
                    auto list_size = type_list_ptr->size;
                    DexTypeItem* type_item_ptr = type_list_ptr->list;
                    for (size_t i = 0; i < list_size; i++) {
                        auto param_class_name_ptr = dex_buf + string_ids[type_ids[type_item_ptr[i].typeIdx].descriptorIdx].stringDataOff;
                        while (*param_class_name_ptr++ & 0x80);
                        os << param_class_name_ptr;
                    }
                }
                auto return_class_name_ptr = dex_buf + string_ids[type_ids[proto_id_ptr->returnTypeIdx].descriptorIdx].stringDataOff;
                while (*return_class_name_ptr++ & 0x80);
                os << ")" << return_class_name_ptr << std::endl;
            }
        };
        parse_methods_array("direct", st_class_data_header.directMethodsSize);
        parse_methods_array("virtual", st_class_data_header.virtualMethodsSize);
    }
}


// Fix code_off, use different space when you want to reconstruct class_data, then update class_dara_off
std::vector<std::pair<int, std::unique_ptr<unsigned char[]>>> restore_method_code(unsigned char* dex_buf, int dex_len, std::unordered_map<int, int>& method_ids_map, std::vector<std::pair<int, std::unique_ptr<char[]>>>& v_dex_code) {
    dex_len = (dex_len + 3) / 4 * 4;// Align the original dex to calculate the offset
    auto code_len = v_dex_code.back().first;// Get the total length of the constructed code
    DexHeader* dex_header_ptr = reinterpret_cast<DexHeader*>(dex_buf);
    DexStringId* string_ids = reinterpret_cast<DexStringId*>(dex_buf + dex_header_ptr->stringIdsOff);
    DexTypeId* type_ids = reinterpret_cast<DexTypeId*>(dex_buf + dex_header_ptr->typeIdsOff);
    DexProtoId* proto_ids = reinterpret_cast<DexProtoId*>(dex_buf + dex_header_ptr->protoIdsOff);
    DexMethodId* method_ids = reinterpret_cast<DexMethodId*>(dex_buf + dex_header_ptr->methodIdsOff);
    DexClassDef* class_defs = reinterpret_cast<DexClassDef*>(dex_buf + dex_header_ptr->classDefsOff);
    auto class_defs_size = dex_header_ptr->classDefsSize;
    std::unordered_set<int> type_ids_set;
    for (auto& method_id : method_ids_map)// Iterate through all the methods to be fixed, find out the class they belong to and cache them, and later, when iterating through the methods in the class, skip the ones that are not there
        type_ids_set.insert(method_ids[method_id.first].classIdx);
    std::vector<std::pair<int, std::unique_ptr<unsigned char[]>>> v_dex_class_data;
    auto tot_new_class_data_len = 0;
    for (u4 class_index = 0; class_index < class_defs_size; class_index++) {
        if (type_ids_set.find(class_defs[class_index].classIdx) == type_ids_set.end())// skip those who don't have
            continue;
        auto class_data_off = class_defs[class_index].classDataOff;
        if (class_data_off == 0)
            continue;
        unsigned char* class_data_ptr = dex_buf + class_data_off;
        DexClassDataHeader st_class_data_header;
        dexReadClassDataHeader(const_cast<const u1**>(&class_data_ptr), &st_class_data_header);
        // Skip attribute fields
        for (size_t i = 0; i < st_class_data_header.staticFieldsSize + st_class_data_header.instanceFieldsSize; i++) {
            readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
            readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
        }
        auto methods_start_ptr = class_data_ptr;// Save the location of the start of the method, which will be used if you want to reconstruct class_data
        auto parse_methods_array = [&](u4 methods_size)->std::pair<bool, int> {
            auto tot_diff = 0;
            auto realloc = false;
            auto method_id = 0;
            for (size_t methods_index = 0; methods_index < methods_size; methods_index++) {
                method_id += readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
                readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
                auto temp = class_data_ptr;// Save the place where the code offset starts, it will be used when rewriting the offset
                auto code_off = readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
                if (method_ids_map.find(method_id) != method_ids_map.end()) {
                    auto new_code_off = dex_len + v_dex_code[method_ids_map[method_id] & 0xffff].first;// only lower 16-bits of id field are useful
                    auto diff = unsignedLeb128Size(new_code_off) - (class_data_ptr - temp);
                    if (diff == 0)// Same length, directly rewrite
                        writeUnsignedLeb128(temp, new_code_off);
                    else {
                        realloc = true;// not the same
                        tot_diff += diff;
                    }
                }
            }
            return std::make_pair(realloc, tot_diff);
        };
        // Iterate separately, as the method start ids are calculated separately
        auto diff_1 = parse_methods_array(st_class_data_header.directMethodsSize);
        auto diff_2 = parse_methods_array(st_class_data_header.virtualMethodsSize);
        if (!diff_1.first && !diff_2.first)// Check if class_data needs to be reconstructed
            continue;
        // Needs to be reconstructed
        class_defs[class_index].classDataOff = dex_len + code_len + tot_new_class_data_len;
        auto new_class_data_len = class_data_ptr - (dex_buf + class_data_off) + diff_1.second + diff_2.second;
        unsigned char* np_new_class_data = new unsigned char[new_class_data_len];
        v_dex_class_data.push_back(std::make_pair(tot_new_class_data_len, std::unique_ptr<unsigned char[]>(np_new_class_data)));
        tot_new_class_data_len += new_class_data_len;
        // Copy the content directly before the method
        np_new_class_data = std::copy(dex_buf + class_data_off, methods_start_ptr, np_new_class_data);
        class_data_ptr = methods_start_ptr;
        auto cp_methods_array = [&](u4 methods_size)->void {
            auto tot_diff = 0;
            auto realloc = false;
            auto method_id = 0;
            for (size_t methods_index = 0; methods_index < methods_size; methods_index++) { // Copy one by one
                auto method_id_diff = readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
                method_id += method_id_diff;
                auto access_flags = readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
                auto code_off = readUnsignedLeb128(const_cast<const u1**>(&class_data_ptr));
                np_new_class_data = writeUnsignedLeb128(np_new_class_data, method_id_diff);
                np_new_class_data = writeUnsignedLeb128(np_new_class_data, access_flags);
                if (method_ids_map.find(method_id) != method_ids_map.end()) {
                    auto new_code_off = dex_len + v_dex_code[method_ids_map[method_id] & 0xffff].first;// Calculate New Offset
                    np_new_class_data = writeUnsignedLeb128(np_new_class_data, new_code_off);
                }
                else
                    np_new_class_data = writeUnsignedLeb128(np_new_class_data, code_off);
            }
        };
        cp_methods_array(st_class_data_header.directMethodsSize);
        cp_methods_array(st_class_data_header.virtualMethodsSize);
    }
    v_dex_class_data.push_back(std::make_pair(tot_new_class_data_len, nullptr));
    return v_dex_class_data;
}

// Write all the contents of the repaired file
void write_new_dex(std::ofstream& ofs, unsigned char* dex_buf, int dex_len, std::vector<std::pair<int, std::unique_ptr<char[]>>>& v_dex_code, std::vector<std::pair<int, std::unique_ptr<unsigned char[]>>>& v_dex_class_data) {
    auto align_dex_len = (dex_len + 3) / 4 * 4;
    auto code_len = v_dex_code.back().first;
    auto new_class_data_len = v_dex_class_data.back().first;
    reinterpret_cast<DexHeader*>(dex_buf)->fileSize = align_dex_len + code_len + new_class_data_len;
    // There's no need to fix if checksum and signature don't affect decompilation
    ofs.write(reinterpret_cast<char*>(dex_buf), dex_len); // Write to original dex
    for (int i = 0; i < align_dex_len - dex_len; i++)// Add Aligned Bytes
        ofs.put(0);
    // Write all repaired DexCode
    for (size_t i = 0; i < v_dex_code.size() - 1; i++)
        ofs.write(v_dex_code[i].second.get(), v_dex_code[i + 1].first - v_dex_code[i].first);
    // Write all the reconstructed class_data
    for (size_t i = 0; i < v_dex_class_data.size() - 1; i++)
        ofs.write(reinterpret_cast<char*>(v_dex_class_data[i].second.get()), v_dex_class_data[i + 1].first - v_dex_class_data[i].first);
}

bool decryptor(std::string str_dex_path) {
    std::unordered_map<int, int> method_ids_map;
    method_ids_map[0x00000023] = 0xAB000000;
    int dex_len;
    auto dex_buf = read_file(str_dex_path, dex_len);
    if (method_ids_map.size() == 0) {
        std::ofstream ofs(str_dex_path + ".methods.txt");
        parse_class_methods(dex_buf.get(), ofs);
        ofs.close();
    }
    else {
        auto v_dex_code = parse_append_data(dex_buf.get(), dex_len);
        auto v_dex_class_data = restore_method_code(dex_buf.get(), dex_len, method_ids_map, v_dex_code);
        std::ofstream ofs(str_dex_path + ".new.dex", std::ofstream::binary);
        write_new_dex(ofs, dex_buf.get(), dex_len, v_dex_code, v_dex_class_data);
        ofs.close();
    }
    return 0;
}

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


CBaiduReinforceUnpackDlg::CBaiduReinforceUnpackDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_BAIDUREINFORCEUNPACK_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CBaiduReinforceUnpackDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CBaiduReinforceUnpackDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_MFCBUTTON1, &CBaiduReinforceUnpackDlg::OnBnClickedMfcbutton1)
    ON_EN_CHANGE(IDC_EDIT1, &CBaiduReinforceUnpackDlg::OnEnChangeEdit1)
    ON_WM_DROPFILES()
    ON_BN_CLICKED(IDC_BUTTON1, &CBaiduReinforceUnpackDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


BOOL CBaiduReinforceUnpackDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();


	SetIcon(m_hIcon, TRUE);	
	SetIcon(m_hIcon, FALSE);	


	return TRUE; 
}

void CBaiduReinforceUnpackDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
    CDialogEx::OnSysCommand(nID, lParam);
}

void CBaiduReinforceUnpackDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this);

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CBaiduReinforceUnpackDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

std::string filename = "";

wchar_t *c2w(const char* c, size_t m_encode = CP_ACP)
{
    int len = MultiByteToWideChar(m_encode, 0, c, strlen(c), NULL, 0);
    wchar_t* m_wchar = new wchar_t[len + 1];
    MultiByteToWideChar(m_encode, 0, c, strlen(c), m_wchar, len);
    m_wchar[len] = '\0';
    return m_wchar;
}

char *w2c(const wchar_t* wp, size_t m_encode = CP_ACP)
{
    int len = WideCharToMultiByte(m_encode, 0, wp, wcslen(wp), NULL, 0, NULL, NULL);
    char* m_char = new char[len + 1];
    WideCharToMultiByte(m_encode, 0, wp, wcslen(wp), m_char, len, NULL, NULL);
    m_char[len] = '\0';
    return m_char;
}

void CBaiduReinforceUnpackDlg::OnBnClickedMfcbutton1()
{
    BOOL isOpen = TRUE;
    CString filter = L"Dalvik Executable(*.dex)|*.dex|All Files(*.*)|*.*||";
    CFileDialog openFileDlg(isOpen, NULL, NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, filter, NULL);
    INT_PTR result = openFileDlg.DoModal();
    if (result == IDOK)
    {
        GetDlgItem(IDC_EDIT1)->SetWindowText(openFileDlg.GetPathName());
        filename = std::string(w2c(openFileDlg.GetPathName()));
    }
}


void CBaiduReinforceUnpackDlg::OnEnChangeEdit1()
{
    CString ls;
    GetDlgItem(IDC_EDIT1)->GetWindowText(ls);
    filename = std::string(w2c(ls));
}


void CBaiduReinforceUnpackDlg::OnDropFiles(HDROP hDropInfo)
{
    UINT count;
    TCHAR filePath[MAX_PATH] = { 0 };
    count = DragQueryFile(hDropInfo, 0xFFFFFFFF, NULL, 0);
    if (count == 1)
    {
        DragQueryFile(hDropInfo, 0, filePath, sizeof(filePath));
        GetDlgItem(IDC_EDIT1)->SetWindowText(filePath);
        filename = std::string(w2c(filePath));
        UpdateData(FALSE);
        DragFinish(hDropInfo); // free temp. occupied memory
        CDialog::OnDropFiles(hDropInfo);
        return;
    }
    else {
        AfxMessageBox(L"Only one file can be accepted at a time");
    }
    CDialogEx::OnDropFiles(hDropInfo);
}


void CBaiduReinforceUnpackDlg::OnBnClickedButton1()
{
    if (decryptor(filename)) {
        CTaskDialog taskdialog(CString(), CString(), CString(), 0);
        taskdialog.SetWindowTitle(L"Success"); 
        taskdialog.SetMainInstruction(L"Decrypted successfully and do you want to open the log?");
        taskdialog.AddCommandControl(10, L"Open");
        taskdialog.AddCommandControl(20, L"Do not open (Delete it simultaneously)");
        taskdialog.SetFooterText(L"Open logs to view details of members of DEX file and operation process records");
        taskdialog.SetFooterIcon(MAKEINTRESOURCEW(-3)); 
        taskdialog.SetVerificationCheckboxText(L"Checked"); 
        taskdialog.SetMainIcon(TD_INFORMATION_ICON); 
        INT_PTR nResult = taskdialog.DoModal(); 
        if (SUCCEEDED(nResult))
        {
            std::string nstr = filename + ".methods.txt";
            switch (taskdialog.GetSelectedCommandControlID())
            {
            case 10: {
                WinExec((std::string("notepad ") + nstr).c_str(), SW_SHOW);
                break;
            }
            case 20: {
                DeleteFile(c2w(nstr.c_str()));
                break;
            }
            default: break;
            }
        }
    }
    else {
        CTaskDialog taskdialog(CString(), CString(), CString(), 0);
        taskdialog.SetWindowTitle(L"Failed to decrypt"); 
        taskdialog.SetMainInstruction(L"Decryption failure, please check if it is the beginning of 2020 baidu encrypted dex file!");
        taskdialog.SetMainIcon(TD_ERROR_ICON);
        taskdialog.SetOptions(TDCBF_OK_BUTTON | TDCBF_CANCEL_BUTTON);
        taskdialog.DoModal();
    }
}

#include "PETools.h"

#include <QStringList>
#include <Windows.h>
#include <TlHelp32.h>
#include <QDebug>
#include <QMessageBox>
#include "sector.h"
#include "Catalogue.h"

PETools::PETools(QWidget* parent)
    : QDialog(parent) {
    ui.setupUi(this);
    setWindowFlags(Qt::Dialog | Qt::WindowSystemMenuHint | Qt::WindowCloseButtonHint);
    initControl();
}

PETools::~PETools() { }

void PETools::initControl() {
    QStringList upHead = { QString::fromLocal8Bit("进程名"),QString::fromLocal8Bit("PID"),QString::fromLocal8Bit("句柄") ,QString::fromLocal8Bit("路径") };

    ui.leftUpTableWidget->setRowCount(1);
    ui.leftUpTableWidget->setColumnCount(upHead.size());
    ui.leftUpTableWidget->setHorizontalHeaderLabels(upHead);
    QHeaderView* upHeader = ui.leftUpTableWidget->verticalHeader();
    upHeader->setHidden(true);
    ui.leftUpTableWidget->horizontalHeader()->setVisible(true);
    ui.leftUpTableWidget->setShowGrid(false);
    ui.leftUpTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui.leftUpTableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui.leftUpTableWidget->horizontalHeader()->setStretchLastSection(true);
    ui.leftUpTableWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    getAllProcesses();
    connectControl();
}

void PETools::connectControl() {
    connect(ui.leftUpTableWidget, &TableWidget::clickLineCount, this, &PETools::setDoubleClickTableItem);
    connect(ui.exit, &QPushButton::clicked, this, &QCoreApplication::quit);
    connect(ui.refreshProgramButton, &QPushButton::clicked, this, &PETools::getAllProcesses);


    connect(ui.about, &QPushButton::clicked, this, [=] {
        QMessageBox::about(nullptr, "About", QString::fromLocal8Bit("PETools Version 1.0\n\nAuthor: Mr.Lv\n\n© 2024 "));
    });

    connect(ui.sectorButton, &QPushButton::clicked, this, [=] {
        if (ui.labelPath->text().isEmpty()) {
            QMessageBox::information(this, "PETools", QString::fromLocal8Bit("请选择程序"));
            return;
        }
        Sector* sector = new Sector;
        emit sector->sendTableData(processInfo_[index_].sectorInfo_);
        QStringList title = ui.labelPath->text().split("\\");
        sector->setWindowTitle(QString::fromLocal8Bit("区段表  ")+title.last());
        sector->show();
    });

    connect(ui.catalogueButton, &QPushButton::clicked, this, [=] {
        if (ui.labelPath->text().isEmpty()) {
            QMessageBox::information(this, "PETools", QString::fromLocal8Bit("请选择程序"));
            return;
        }
        Catalogue* catalogue = new Catalogue;
        emit catalogue->sendTableData(processInfo_[index_].catalogueInfo_);
        QStringList title = ui.labelPath->text().split("\\");
        catalogue->setWindowTitle(QString::fromLocal8Bit("目录表  ")+title.last());
        catalogue->show();
    });

}

void PETools::getAllProcesses() {
    processInfo_.clear();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return;

    }

    int index = 0;
    do {
        processInfo_.push_back(ProcessInfo());
        processInfo_[index].peHandInfo_.processName_ = QString::fromLocal8Bit(pe32.szExeFile, BASE_DATA).rightJustified(8, '0');
        processInfo_[index].peHandInfo_.processPID_ = QString::number(pe32.th32ProcessID, BASE_DATA).rightJustified(8, '0');

        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);
        HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe32.th32ProcessID);
        if (hModuleSnap != INVALID_HANDLE_VALUE) {
            if (Module32First(hModuleSnap, &me32)) {
                processInfo_[index].peHandInfo_.processHandle_ = QString::number(reinterpret_cast<uintptr_t>( OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID) ), BASE_DATA).rightJustified(8, '0');
                processInfo_[index].peHandInfo_.processPath_ = QString::fromLocal8Bit(me32.szExePath);
            }
        }

        ++index;

    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    updateTableWidget();

}

void PETools::updateTableWidget() {
    ui.leftUpTableWidget->clearContents();
    int dataSize = processInfo_.size();
    QTableWidgetItem* item = nullptr;
    ui.leftUpTableWidget->setRowCount(dataSize);
    for (int i = 0; i < dataSize; ++i) {
        ui.leftUpTableWidget->setItem(i, 0, new QTableWidgetItem(processInfo_[i].peHandInfo_.processName_));

        item = new QTableWidgetItem(processInfo_[i].peHandInfo_.processPID_);
        item->setTextAlignment(Qt::AlignCenter);
        ui.leftUpTableWidget->setItem(i, 1, item);

        item = new QTableWidgetItem(processInfo_[i].peHandInfo_.processHandle_);
        item->setTextAlignment(Qt::AlignCenter);
        ui.leftUpTableWidget->setItem(i, 2, item);

        ui.leftUpTableWidget->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(processInfo_[i].peHandInfo_.processPath_)));
    }
}

void PETools::setDoubleClickTableItem(const int& index) {
    index_ = index;
    readProcessDetails();
    setLabelText();
}


void PETools::setLabelText() {

    const auto& peHandInfo = processInfo_[index_].peHandInfo_;
    if (peHandInfo.processPath_.isEmpty()) {
        ui.labelPath->clear();
        return;
    }

    QString labelText = peHandInfo.processPath_;
    ui.labelPath->setText(labelText);
    ui.showLabel->setText(QString::fromLocal8Bit("当前选中文件 %1").arg(labelText));

    struct LabelMapping {
        QLabel* label;
        QString value;
    };

    QVector<LabelMapping> labelMappings = {
        { ui.labelEntrance, peHandInfo.processShowEntrance_ },
        { ui.LabelMirrorBase, peHandInfo.processShowBaseAddr_ },
        { ui.LabelMirrorSize, peHandInfo.processShowBaseSize_ },
        { ui.LabelCodeBase, peHandInfo.processShowCodeBaseAddr_ },
        { ui.LabelDataBase, peHandInfo.processShowDataBaseAddr_ },
        { ui.LabelBlockAligning, peHandInfo.processShowBlockAlignment_ },
        { ui.LabelFileBlockAligning, peHandInfo.processShowFileAlignment_ },
        { ui.LabelMagic, peHandInfo.processShowMagic_ },
        { ui.LabelSubsystem, peHandInfo.processShowSubsystem_ },
        { ui.LabelSectorNumber, peHandInfo.processShowNumberOfSections_ },
        { ui.LabelDataMark, peHandInfo.processShowDataMark_ },
        { ui.LabelHeaderSize, peHandInfo.processShowHanderSize_ },
        { ui.LabelEigenValue, peHandInfo.processShowEigenValue_ },
        { ui.LabelChecksum, peHandInfo.processShowChecksum_ },
        { ui.LabelSelectableHanderSize, peHandInfo.processShowSelectableHanderSize_ },
        { ui.LabelRVANumber, peHandInfo.processShowRVANumber_ }
    };

    for (const auto& mapping : labelMappings) {
        mapping.label->setText(mapping.value);
    }
}

DWORD PETools::RVA2Offset(PIMAGE_NT_HEADERS pNTHeader, DWORD dwExpotRVA) {
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER) ( (DWORD) pNTHeader + sizeof(IMAGE_NT_HEADERS) );

    for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++) {
        if (dwExpotRVA >= pSection[i].VirtualAddress && dwExpotRVA < ( pSection[i].VirtualAddress + pSection[i].SizeOfRawData )) {
            return pSection[i].PointerToRawData + ( dwExpotRVA - pSection[i].VirtualAddress );
        }
    }

    return 0;
}

void CheckError(const std::string& functionName) {
    DWORD errorCode = GetLastError();
    if (errorCode != ERROR_SUCCESS) {
        LPVOID errorMsg;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR) &errorMsg,
            0,
            NULL
        );
        qDebug() << L"Error in " << functionName.c_str() << L": " << errorMsg ;
        LocalFree(errorMsg);
    }
}


void PETools::readProcessDetails() {
    bool baseData;
    const int Pid = processInfo_[index_].peHandInfo_.processPID_.toInt(&baseData, 16);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
    if (!hProcess && !baseData) {
        return;
    }

    // Retrieve process information
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, Pid);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        CloseHandle(hModuleSnap);
        return;
    }
    if (!Module32First(hModuleSnap, &me32)) {
        CloseHandle(hModuleSnap);
        CloseHandle(hProcess);
        return;
    }

    BYTE dosBuffer[4096]; // Buffer to store PE header
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, me32.modBaseAddr, dosBuffer, sizeof(dosBuffer), &bytesRead) || bytesRead != sizeof(dosBuffer)) {
        CloseHandle(hModuleSnap);
        CloseHandle(hProcess);
        return;
    }
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>( dosBuffer );
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hModuleSnap);
        CloseHandle(hProcess);
        return;
    }

    PIMAGE_NT_HEADERS pImageHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>( dosBuffer + dosHeader->e_lfanew );
    if (pImageHeaders->Signature != IMAGE_NT_SIGNATURE) {

        CloseHandle(hModuleSnap);
        CloseHandle(hProcess);
        return;
    }
    PEHandInfo& peHandInfo = processInfo_[index_].peHandInfo_;
    fillDataProcessInfo(peHandInfo, pImageHeaders);
    fillDataSectorInfo(processInfo_[index_].sectorInfo_, pImageHeaders);
    fillDataCatalogueInfo(processInfo_[index_].catalogueInfo_, pImageHeaders);

    printf("<--------------------Export Table-------------------->\n");

    HANDLE hFile = CreateFile("D:\\Project\\DLL\\DllWindow\\x64\\Debug\\DllWindow.dll", GENERIC_ALL, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL); //获得PE文件句柄
    if (hFile == INVALID_HANDLE_VALUE) {
        CheckError("CreateFile");
        return;
    }

    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL); //创建一个新的文件映射内核对象
    if (!hMapping) {
        CheckError("CreateFileMapping");
        CloseHandle(hFile);
        return;
    }

    //将一个文件映射对象映射到内存,得到指向映射到内存的第一个字节的指针pbFile
    PVOID pbFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!pbFile) {
        CheckError("MapViewOfFile");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) pbFile;//pDosHeader指向DOS头起始位置
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        qDebug() << "Invalid DOS signature.";
        UnmapViewOfFile(pbFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    if (INVALID_HANDLE_VALUE == hFile || NULL == hMapping || NULL == pbFile) {
        printf("\n\t---------- The File Inexistence! ----------\n");
        if (NULL != pbFile) {
            UnmapViewOfFile(pbFile);
        }

        if (NULL != hMapping) {
            CloseHandle(hMapping);
        }

        if (INVALID_HANDLE_VALUE != hFile) {
            CloseHandle(hFile);
        }

        return;
    }

    printf("PE Header e_lfanew：0x%x\n", pDosHeader->e_lfanew);
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS) ( (DWORD) pbFile + pDosHeader->e_lfanew );//计算PE头位置

    DWORD dwExportOffset = RVA2Offset(pNTHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY) ( (DWORD) pbFile + dwExportOffset );
    DWORD dwFunctionNameOffset = (DWORD) pbFile + RVA2Offset(pNTHeader, pExport->Name);
    DWORD* pdwNamesAddress = (DWORD*) ( (DWORD) pbFile + RVA2Offset(pNTHeader, pExport->AddressOfNames) );
    DWORD* pdwFunctionAddress = (DWORD*) ( (DWORD) pbFile + RVA2Offset(pNTHeader, pExport->AddressOfFunctions) );
    WORD* pwOrdinals = (WORD*) ( (DWORD) pbFile + RVA2Offset(pNTHeader, pExport->AddressOfNameOrdinals) );

    printf("AddressOfNameOrdinals: 0x%08X\n", RVA2Offset(pNTHeader, pExport->AddressOfNameOrdinals));
    printf("AddressOfFunctions: 0x%08X\n", RVA2Offset(pNTHeader, pExport->AddressOfFunctions));
    printf("AddressOfNames: 0x%08X\n", RVA2Offset(pNTHeader, pExport->AddressOfNames));
    if (0 == pExport->NumberOfFunctions) {
        printf("\n\t---------- No Export Tabel! ----------\n");
        if (NULL != pbFile) {
            UnmapViewOfFile(pbFile);
        }

        if (NULL != hMapping) {
            CloseHandle(hMapping);
        }

        if (INVALID_HANDLE_VALUE != hFile) {
            CloseHandle(hFile);
        }

        return;
    }

    printf("FileName: %s\n", dwFunctionNameOffset);
    printf("NumberOfFunctions: %d\n", pExport->NumberOfFunctions);
    printf("NumberOfNames: %d\n\n", pExport->NumberOfNames);
    printf("============NameExport:\n\n");

    int IsFound[1000] = { 0 };
    int k;
    for (k = 0; k < pExport->NumberOfFunctions; k++) {
        IsFound[k] = 0;
        //printf("%d ",IsFound[k]);
    }
    int i;
    for (i = 0; i < pExport->NumberOfNames; i++) {
        DWORD dwFunctionAddress = pdwFunctionAddress[pwOrdinals[i]];
        DWORD pdwFunNameOffset = (DWORD) pbFile + RVA2Offset(pNTHeader, pdwNamesAddress[i]);
        IsFound[pwOrdinals[i]] = 1;
        printf("[ExportNum]: %-4d  [Name]: %-30s [RVA]: 0x%08X\n", pExport->Base + pwOrdinals[i], pdwFunNameOffset, dwFunctionAddress);
    }

    printf("\n============NumberExport:\n");

    int m;
    for (m = 0; m < pExport->NumberOfFunctions; m++) {
        if (IsFound[m] != 1) {
            DWORD dwFunctionAddress = pdwFunctionAddress[m];
            printf("[ExportNum]: %-4d [RVA]: 0x%08X\n", pExport->Base + m, dwFunctionAddress);
        }
    }

    printf("\n");


    CloseHandle(hModuleSnap);
    CloseHandle(hProcess);
}

void PETools::fillDataProcessInfo(PEHandInfo& peHandInfo, PIMAGE_NT_HEADERS &pImageHeaders) {
    peHandInfo.processShowEntrance_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.AddressOfEntryPoint, 8, 16, QChar('0'));
    peHandInfo.processShowBaseAddr_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.ImageBase, 8, 16, QChar('0'));
    peHandInfo.processShowBaseSize_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.SizeOfImage, 8, 16, QChar('0'));
    peHandInfo.processShowCodeBaseAddr_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.BaseOfCode, 8, 16, QChar('0'));
    if (pImageHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>( pImageHeaders );
        peHandInfo.processShowDataBaseAddr_ = QString("0x%1").arg(ntHeaders32->OptionalHeader.BaseOfData, 8, 16, QChar('0'));
    }
    peHandInfo.processShowBlockAlignment_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.SectionAlignment, 8, 16, QChar('0'));
    peHandInfo.processShowFileAlignment_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.FileAlignment, 8, 16, QChar('0'));
    peHandInfo.processShowMagic_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.Magic, 8, 16, QChar('0'));
    peHandInfo.processShowSubsystem_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.Subsystem, 8, 16, QChar('0'));
    peHandInfo.processShowNumberOfSections_ = QString("0x%1").arg(pImageHeaders->FileHeader.NumberOfSections, 8, 16, QChar('0'));
    peHandInfo.processShowDataMark_ = QString("0x%1").arg(pImageHeaders->FileHeader.TimeDateStamp, 8, 16, QChar('0'));
    peHandInfo.processShowHanderSize_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.SizeOfHeaders, 8, 16, QChar('0'));
    peHandInfo.processShowEigenValue_ = QString("0x%1").arg(pImageHeaders->FileHeader.Characteristics, 8, 16, QChar('0'));
    peHandInfo.processShowChecksum_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.CheckSum, 8, 16, QChar('0'));
    peHandInfo.processShowSelectableHanderSize_ = QString("0x%1").arg(pImageHeaders->FileHeader.SizeOfOptionalHeader, 8, 16, QChar('0'));
    peHandInfo.processShowRVANumber_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.NumberOfRvaAndSizes, 8, 16, QChar('0'));
}

void PETools::fillDataSectorInfo(QVector<SectorInfo>& sectorInfo, PIMAGE_NT_HEADERS& pImageHeaders) {
    DWORD dwSectionNum = pImageHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pSectorHeader = IMAGE_FIRST_SECTION(pImageHeaders);
    for (DWORD i = 0; i < dwSectionNum; i++, pSectorHeader++) {
        SectorInfo sector;
        sector.sectorName_ = QString::fromLocal8Bit(reinterpret_cast<char*>( pSectorHeader->Name ), strnlen(reinterpret_cast<char*>( pSectorHeader->Name ), IMAGE_SIZEOF_SHORT_NAME));
        sector.sectorVOffset_ = QString("0x%1").arg(pSectorHeader->VirtualAddress, 8, BASE_DATA, QChar('0'));
        sector.sectorVSize_ = QString("0x%1").arg(pSectorHeader->Misc.VirtualSize, 8, BASE_DATA, QChar('0'));
        sector.sectorROffset_ = QString("0x%1").arg(pSectorHeader->PointerToRawData, 8, BASE_DATA, QChar('0'));
        sector.sectorRSize_ = QString("0x%1").arg(pSectorHeader->SizeOfRawData, 8, BASE_DATA, QChar('0'));
        sector.sectorMark_ = QString("0x%1").arg(pSectorHeader->Characteristics, 8, BASE_DATA, QChar('0'));
        sectorInfo.push_back(sector);
    }
}

void PETools::fillDataCatalogueInfo(QVector<CatalogueInfo>& catalogueInfo, PIMAGE_NT_HEADERS& pImageHeaders) {
    for (DWORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        CatalogueInfo catalogue;
        catalogue.catalogueVirtualAddress_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.DataDirectory[i].VirtualAddress, 8, BASE_DATA, QChar('0'));
        catalogue.catalogueSize_ = QString("0x%1").arg(pImageHeaders->OptionalHeader.DataDirectory[i].Size, 8, BASE_DATA, QChar('0'));
        catalogueInfo.push_back(catalogue);
    }
}

void PETools::fillImportTable(HANDLE &hProcess, BYTE* fileData, PIMAGE_NT_HEADERS &pImageHeaders, QVector<QString>& importTable) {
    DWORD importDirectoryRVA = pImageHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importDirectoryRVA) {
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>( fileData + importDirectoryRVA );

    while (importDescriptor->Name) {
        const char* dllName = reinterpret_cast<const char*>( fileData + importDescriptor->Name );
        importTable.append(QString("DLL: %1").arg(QString::fromLocal8Bit(dllName)));

        PIMAGE_THUNK_DATA thunkData = reinterpret_cast<PIMAGE_THUNK_DATA>( fileData + importDescriptor->OriginalFirstThunk );

        while (thunkData->u1.AddressOfData) {
            if (thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                importTable.append(QString("Ordinal: %1").arg(thunkData->u1.Ordinal & 0xFFFF));
            } else {
                PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>( fileData + thunkData->u1.AddressOfData );
                importTable.append(QString("Function: %1").arg(QString::fromLocal8Bit(importByName->Name)));
            }
            thunkData++;
        }
        importDescriptor++;
    }
    for (auto& a : importTable) { 
        qDebug() << a;
    }
}
#pragma once

#include <QtWidgets/QDialog>
#include "ui_PETools.h"
#include "ProcessInfo.h"

#include <QStandardItemModel>

#define BASE_DATA 16

class PETools : public QDialog
{
    Q_OBJECT

public:
    PETools(QWidget *parent = nullptr);
    ~PETools();

protected:
    void initControl();
    void connectControl();

    void getAllProcesses();
    void updateTableWidget();
private:
    void setDoubleClickTableItem(const int& index);
    void setLabelText();
    void readProcessDetails();
    void fillDataProcessInfo(PEHandInfo& peHandInfo, PIMAGE_NT_HEADERS &pImageHeaders);
    void fillDataSectorInfo(QVector<SectorInfo>& sectorInfo, PIMAGE_NT_HEADERS& pImageHeaders);
    void fillDataCatalogueInfo(QVector<CatalogueInfo>& sectorInfo, PIMAGE_NT_HEADERS& pImageHeaders);
    void fillImportTable(HANDLE& hProcess, BYTE* fileData, PIMAGE_NT_HEADERS& pImageHeaders, QVector<QString>& importTable);
    DWORD RVA2Offset(PIMAGE_NT_HEADERS pNTHeader, DWORD dwExpotRVA);
private:
    QVector<ProcessInfo> processInfo_;
    int index_;

private:
    Ui::PEToolsClass ui;
};

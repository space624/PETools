#include "Sector.h"
#include "PETools.h"
#include "ProcessInfo.h"
#include <QVector>

Sector::Sector(QWidget *parent)
    : QDialog(parent)
{
    ui.setupUi(this);
    //setWindowTitle(QString::fromLocal8Bit("区段表"));
    initTableWidget();
    connect(this, &Sector::sendTableData, this, &Sector::updateSectorTableWidget);
}

Sector::~Sector()
{}

void Sector::updateSectorTableWidget(const QVector<SectorInfo>& sector) {
   
    ui.sectorTableWidget->clearContents();
    int dataSize = sector.size();
    QTableWidgetItem* item = nullptr;
    ui.sectorTableWidget->setRowCount(dataSize);
    for (int i = 0; i < dataSize; ++i) {
        item = new QTableWidgetItem(sector[i].sectorName_);
        item->setTextAlignment(Qt::AlignCenter);
        ui.sectorTableWidget->setItem(i, 0, item);

        item = new QTableWidgetItem(sector[i].sectorVOffset_);
        item->setTextAlignment(Qt::AlignCenter);
        ui.sectorTableWidget->setItem(i, 1, item);

        item = new QTableWidgetItem(sector[i].sectorVSize_);
        item->setTextAlignment(Qt::AlignCenter);
        ui.sectorTableWidget->setItem(i, 2, item);

        item = new QTableWidgetItem(sector[i].sectorVSize_);
        item->setTextAlignment(Qt::AlignCenter);
        ui.sectorTableWidget->setItem(i, 3, item);

        item = new QTableWidgetItem(sector[i].sectorROffset_);
        item->setTextAlignment(Qt::AlignCenter);
        ui.sectorTableWidget->setItem(i, 4, item);

        item = new QTableWidgetItem(sector[i].sectorRSize_);
        item->setTextAlignment(Qt::AlignCenter);
        ui.sectorTableWidget->setItem(i, 5, item);

        item = new QTableWidgetItem(sector[i].sectorMark_);
        item->setTextAlignment(Qt::AlignCenter);
        ui.sectorTableWidget->setItem(i, 6, item);
    }
}

void Sector::initTableWidget() {
    QStringList sectorHead = { QString::fromLocal8Bit("区段名"),QString::fromLocal8Bit("VOffset"),QString::fromLocal8Bit("VSize") ,QString::fromLocal8Bit("ROffset"),QString::fromLocal8Bit("RSize"),QString::fromLocal8Bit("标志") };
    ui.sectorTableWidget->setColumnCount(sectorHead.size());
    ui.sectorTableWidget->setHorizontalHeaderLabels(sectorHead);
    QHeaderView* upHeader = ui.sectorTableWidget->verticalHeader();
    upHeader->setHidden(true);
    ui.sectorTableWidget->horizontalHeader()->setVisible(true);
    ui.sectorTableWidget->setShowGrid(false);
    ui.sectorTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui.sectorTableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui.sectorTableWidget->horizontalHeader()->setStretchLastSection(true);
    //ui.leftUpTableWidget->resizeColumnsToContents();
    ui.sectorTableWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
}

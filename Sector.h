#pragma once

#include <QDialog>
#include "ui_Sector.h"
#include "ProcessInfo.h"

class Sector : public QDialog {
    Q_OBJECT

public:
    Sector(QWidget* parent = nullptr);
    ~Sector();

    void updateSectorTableWidget(const QVector<SectorInfo>& sector);
signals:
    void sendTableData(const QVector<SectorInfo>&);

private:
    void initTableWidget();

private:
    Ui::SectorClass ui;
};

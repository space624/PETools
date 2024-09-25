#pragma once

#include <QDialog>
#include "ui_Catalogue.h"
#include "ProcessInfo.h"
class Catalogue : public QDialog
{
    Q_OBJECT

public:
    Catalogue(QWidget *parent = nullptr);
    ~Catalogue();

    void updateLabel(const QVector<CatalogueInfo>& catalogue);
signals:
    void sendTableData(const QVector<CatalogueInfo>&);

private:
    Ui::CatalogueClass ui;
};

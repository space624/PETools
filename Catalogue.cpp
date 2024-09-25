#include "Catalogue.h"

#include <QDebug>
Catalogue::Catalogue(QWidget* parent)
    : QDialog(parent) {
    ui.setupUi(this);
    //setWindowTitle(QString::fromLocal8Bit("Ä¿Â¼±í"));
    connect(this, &Catalogue::sendTableData, this, &Catalogue::updateLabel);
}

Catalogue::~Catalogue() { }

void Catalogue::updateLabel(const QVector<CatalogueInfo>& catalogue) {

    struct LabelMapping {
        QLabel* rvaLabel;
        QLabel* sizeLabel;
    };

    QVector<LabelMapping> labelMappings = {
        { ui.LabelCatalogueOutRVA, ui.LabelCatalogueOutSize },
        { ui.LabelCatalogueInRVA, ui.LabelCatalogueInSize },
        { ui.LabelCatalogueResourceRVA, ui.LabelCatalogueResourceSize },
        { ui.LabelCatalogueAbnormalRVA, ui.LabelCatalogueAbnormalSize },
        { ui.LabelCatalogueSafetyRVA, ui.LabelCatalogueSafetySize },
        { ui.LabelCatalogueRedirectRVA, ui.LabelCatalogueRedirectSize },
        { ui.LabelCatalogueDebugRVA, ui.LabelCatalogueDebugSize },
        { ui.LabelCatalogueCopyrightRVA, ui.LabelCatalogueCopyrightSize },
        { ui.LabelCatalogueGlobalPointerRVA, ui.LabelCatalogueGlobalPointerSize },
        { ui.LabelcatalogueTLSTableRVA, ui.LabelcatalogueTLSTableSize },
        { ui.LabelCatalogueLoadConfigurationRVA, ui.LabelCatalogueLoadConfigurationSize },
        { ui.LabelCatalogueBindInputRVA, ui.LabelCatalogueBindInputSize },
        { ui.LabelCatalogueIATRVA, ui.LabelCatalogueIATSize },
        { ui.LabelCatalogueDelayedInputRVA, ui.LabelCatalogueDelayedInputSize },
        { ui.LabelCatalogueCOMRVA, ui.LabelCatalogueCOMSize },
        { ui.LabelCatalogueReserveRVA, ui.LabelCatalogueReserveSize }
    };

    for (int i = 0; i < catalogue.size(); ++i) {
        labelMappings[i].rvaLabel->setText(catalogue[i].catalogueVirtualAddress_);
        labelMappings[i].sizeLabel->setText(catalogue[i].catalogueSize_);
    }

}

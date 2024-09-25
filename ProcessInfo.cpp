#include "ProcessInfo.h"

/*-----------------------------------------------------*/

SectorInfo::SectorInfo() {
    initDefaultValue();
}

void SectorInfo::initDefaultValue() {
    QString addr = "0x00000000";
    sectorName_ = addr;
    sectorVOffset_ = addr;
    sectorVSize_ = addr;
    sectorROffset_ = addr;
    sectorRSize_ = addr;
    sectorMark_ = addr;
}

CatalogueInfo::CatalogueInfo() {
    initDefaultValue();
}

void CatalogueInfo::initDefaultValue() {
    QString addr = "0x00000000";

    catalogueVirtualAddress_ = addr;
    catalogueSize_ = addr;
}

PEHandInfo::PEHandInfo() {
    initDefaultValue();
}

void PEHandInfo::initDefaultValue() {
    QString addr = "0x00000000";

    processShowEntrance_ = addr;
    processShowBaseAddr_ = addr;
    processShowBaseSize_ = addr;
    processShowCodeBaseAddr_ = addr;
    processShowDataBaseAddr_ = addr;
    processShowBlockAlignment_ = addr;
    processShowFileAlignment_ = addr;
    processShowMagic_ = addr;
    processShowSubsystem_ = addr;
    processShowNumberOfSections_ = addr;
    processShowDataMark_ = addr;
    processShowHanderSize_ = addr;
    processShowEigenValue_ = addr;
    processShowChecksum_ = addr;
    processShowSelectableHanderSize_ = addr;
    processShowRVANumber_ = addr;
}

#pragma once
#include <QString>
#include <QVector>
#include <Windows.h>

struct PEHandInfo {

public:
    PEHandInfo();
private:
    void initDefaultValue();

public:
    QString processName_;
    QString processPID_;
    QString processHandle_;
    QString processPath_;

    QString processShowEntrance_;
    QString processShowBaseAddr_;
    QString processShowBaseSize_;
    QString processShowCodeBaseAddr_;
    QString processShowDataBaseAddr_;
    QString processShowBlockAlignment_;
    QString processShowFileAlignment_;
    QString processShowMagic_;
    QString processShowSubsystem_;
    QString processShowNumberOfSections_;
    QString processShowDataMark_;
    QString processShowHanderSize_;
    QString processShowEigenValue_;
    QString processShowChecksum_;
    QString processShowSelectableHanderSize_;
    QString processShowRVANumber_;
};

struct SectorInfo {
    SectorInfo();

private:
    void initDefaultValue();
public:
    QString sectorName_;
    QString sectorVOffset_;
    QString sectorVSize_;
    QString sectorROffset_;
    QString sectorRSize_;
    QString sectorMark_;
};


struct CatalogueInfo {
    CatalogueInfo();

private:
    void initDefaultValue();
public:
    //[0] : RVA
    //[1] : SIZE
    //QString catalogueOut_[1];               //�����
    //QString catalogueIn_[1];                //�����
    //QString catalogueResource_[1];          //��Դ    
    //QString catalogueAbnormal_[1];          //�쳣     
    //QString catalogueSafety_[1];            //��ȫ     
    //QString catalogueRedirect_[1];          //�ض��� 
    //QString catalogueDebug_[1];             //����
    //QString catalogueCopyright_[1];         //��Ȩ
    //QString catalogueGlobalPointer_[1];     //ȫ��ָ��
    //QString catalogueTLSTable_[1];          //TLS��
    //QString catalogueLoadConfiguration_[1]; //��������
    //QString catalogueBindInput_[1];         //������
    //QString catalogueIAT_[1];               //IAT
    //QString catalogueDelayedInput_[1];      //�ӳ�����
    //QString catalogueCOM_[1];               //COM
    //QString catalogueReserve_[1];           //����
    QString catalogueVirtualAddress_;
    QString catalogueSize_;
};


struct ProcessInfo {
public:
    PEHandInfo peHandInfo_;
    QVector<SectorInfo> sectorInfo_;
    QVector<CatalogueInfo> catalogueInfo_;
};


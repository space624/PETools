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
    //QString catalogueOut_[1];               //输出表
    //QString catalogueIn_[1];                //输入表
    //QString catalogueResource_[1];          //资源    
    //QString catalogueAbnormal_[1];          //异常     
    //QString catalogueSafety_[1];            //安全     
    //QString catalogueRedirect_[1];          //重定向 
    //QString catalogueDebug_[1];             //调试
    //QString catalogueCopyright_[1];         //版权
    //QString catalogueGlobalPointer_[1];     //全局指针
    //QString catalogueTLSTable_[1];          //TLS表
    //QString catalogueLoadConfiguration_[1]; //载入配置
    //QString catalogueBindInput_[1];         //绑定输入
    //QString catalogueIAT_[1];               //IAT
    //QString catalogueDelayedInput_[1];      //延迟输入
    //QString catalogueCOM_[1];               //COM
    //QString catalogueReserve_[1];           //保留
    QString catalogueVirtualAddress_;
    QString catalogueSize_;
};


struct ProcessInfo {
public:
    PEHandInfo peHandInfo_;
    QVector<SectorInfo> sectorInfo_;
    QVector<CatalogueInfo> catalogueInfo_;
};


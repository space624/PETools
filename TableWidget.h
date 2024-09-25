#pragma once
#include <QTableWidget>

class TableWidget :public QTableWidget { 
    Q_OBJECT
public:
    TableWidget(QWidget* parent = nullptr);

protected:
    void mouseDoubleClickEvent(QMouseEvent* event) override;

signals:
    void clickLineCount(const int &count);
};


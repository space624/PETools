#include "TableWidget.h"

#include <QMouseEvent>
#include <QDebug>

TableWidget::TableWidget(QWidget* parent) :QTableWidget(parent) { }

void TableWidget::mouseDoubleClickEvent(QMouseEvent* event) {

    QTableWidget::mouseDoubleClickEvent(event);

    // 获取鼠标双击事件的发生位置
    QPoint pos = event->pos();

    // 获取目标单元格的行列索引
    QTableWidgetItem* item = itemAt(pos);
    if (item) {
        // 打印双击的单元格的行列索引和数据
        emit clickLineCount(item->row());
        //qDebug() << "Double clicked at row:" << item->row() << ", data:" << item->text();
    }

}

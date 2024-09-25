#include "TableWidget.h"

#include <QMouseEvent>
#include <QDebug>

TableWidget::TableWidget(QWidget* parent) :QTableWidget(parent) { }

void TableWidget::mouseDoubleClickEvent(QMouseEvent* event) {

    QTableWidget::mouseDoubleClickEvent(event);

    // ��ȡ���˫���¼��ķ���λ��
    QPoint pos = event->pos();

    // ��ȡĿ�굥Ԫ�����������
    QTableWidgetItem* item = itemAt(pos);
    if (item) {
        // ��ӡ˫���ĵ�Ԫ�����������������
        emit clickLineCount(item->row());
        //qDebug() << "Double clicked at row:" << item->row() << ", data:" << item->text();
    }

}

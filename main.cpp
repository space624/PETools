#include "PETools.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    PETools w;
    w.show();
    return a.exec();
}

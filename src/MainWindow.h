#pragma once

#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QComboBox>
#include <QLabel>
#include <QSplitter>
#include <QTreeWidget>
#include <QPlainTextEdit>
#include <QVector>
#include "PacketCapture.h"
#include "PacketData.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override = default;

private slots:
    void onStartCapture();
    void onStopCapture();
    void onPacketCaptured(PacketData packet);
    void onCaptureError(const QString &errorMsg);
    void onPacketSelectionChanged();

private:
    void setupUi();
    void populateDetailTree(const PacketData &pkt);
    void populateHexView(const QByteArray &data);
    static QString formatHexDump(const QByteArray &data);
    static QString tcpFlagsStr(uint8_t flags);

    // ── Toolbar / controls ────────────────────────────────
    QComboBox   *interfaceCombo;
    QPushButton *startBtn;
    QPushButton *stopBtn;
    QLabel      *statusLabel;

    // ── Three-pane layout ─────────────────────────────────
    QSplitter    *mainSplitter;
    QTableWidget *packetTable;
    QTreeWidget  *detailTree;
    QPlainTextEdit *hexView;

    // ── Capture engine + packet store ─────────────────────
    PacketCapture        *captureEngine;
    QVector<PacketData>   m_packets;
};

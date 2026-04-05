#include "MainWindow.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QTreeWidgetItem>
#include <QFont>
#include <QColor>
#include <QFrame>

// ─────────────────────────────────────────────────────────────────────────────
//  Constructor
// ─────────────────────────────────────────────────────────────────────────────

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setupUi();

    captureEngine = new PacketCapture(this);

    connect(captureEngine, &PacketCapture::packetCaptured,
            this, &MainWindow::onPacketCaptured);
    connect(captureEngine, &PacketCapture::captureError,
            this, &MainWindow::onCaptureError);
}

// ─────────────────────────────────────────────────────────────────────────────
//  UI setup
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::setupUi() {
    setWindowTitle("Wireshark Clone");
    resize(1280, 800);

    // ── Application-wide dark stylesheet ────────────────────────────────────
    setStyleSheet(R"(
        QMainWindow, QWidget {
            background-color: #1e1e2e;
            color: #cdd6f4;
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
        }
        QTableWidget {
            background-color: #181825;
            alternate-background-color: #1e1e2e;
            gridline-color: #313244;
            selection-background-color: #45475a;
            selection-color: #cdd6f4;
            border: 1px solid #313244;
        }
        QTableWidget::item { padding: 2px 6px; }
        QHeaderView::section {
            background-color: #313244;
            color: #89b4fa;
            padding: 5px 8px;
            border: none;
            border-right: 1px solid #45475a;
            font-weight: bold;
        }
        QTreeWidget {
            background-color: #181825;
            alternate-background-color: #1e1e2e;
            border: 1px solid #313244;
        }
        QTreeWidget::item { padding: 2px 4px; }
        QTreeWidget::item:selected {
            background-color: #45475a;
            color: #cdd6f4;
        }
        QTreeWidget::branch:has-children:!has-siblings:closed,
        QTreeWidget::branch:closed:has-children:has-siblings {
            image: none;
        }
        QPlainTextEdit {
            background-color: #11111b;
            color: #a6e3a1;
            border: 1px solid #313244;
            selection-background-color: #45475a;
        }
        QComboBox {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
            border-radius: 4px;
            padding: 4px 8px;
            min-width: 360px;
        }
        QComboBox::drop-down { border: none; }
        QComboBox QAbstractItemView {
            background-color: #313244;
            color: #cdd6f4;
            selection-background-color: #45475a;
        }
        QPushButton {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
            border-radius: 4px;
            padding: 5px 14px;
            font-weight: bold;
        }
        QPushButton:hover  { background-color: #45475a; }
        QPushButton:pressed { background-color: #585b70; }
        QPushButton:disabled { color: #585b70; border-color: #313244; }
        QPushButton#startBtn { color: #a6e3a1; border-color: #a6e3a1; }
        QPushButton#startBtn:hover { background-color: #a6e3a1; color: #1e1e2e; }
        QPushButton#stopBtn  { color: #f38ba8; border-color: #f38ba8; }
        QPushButton#stopBtn:hover { background-color: #f38ba8; color: #1e1e2e; }
        QLabel { color: #bac2de; }
        QLabel#statusLabel { color: #89dceb; font-style: italic; }
        QSplitter::handle {
            background-color: #313244;
            height: 3px;
            width: 3px;
        }
        QScrollBar:vertical {
            background: #181825;
            width: 10px;
        }
        QScrollBar::handle:vertical {
            background: #45475a;
            border-radius: 4px;
            min-height: 20px;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
    )");

    // ── Central widget & root layout ─────────────────────────────────────────
    QWidget    *central    = new QWidget(this);
    QVBoxLayout *rootLayout = new QVBoxLayout(central);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(6);
    setCentralWidget(central);

    // ── Toolbar row ──────────────────────────────────────────────────────────
    QHBoxLayout *toolBar = new QHBoxLayout();
    toolBar->setSpacing(8);

    interfaceCombo = new QComboBox(this);
    startBtn       = new QPushButton("▶  Start Capture", this);
    stopBtn        = new QPushButton("■  Stop Capture",  this);
    statusLabel    = new QLabel("Ready", this);

    startBtn->setObjectName("startBtn");
    stopBtn->setObjectName("stopBtn");
    statusLabel->setObjectName("statusLabel");

    stopBtn->setEnabled(false);

    toolBar->addWidget(interfaceCombo);
    toolBar->addWidget(startBtn);
    toolBar->addWidget(stopBtn);
    toolBar->addStretch();
    toolBar->addWidget(statusLabel);

    rootLayout->addLayout(toolBar);

    // ── Three-pane vertical splitter ─────────────────────────────────────────
    mainSplitter = new QSplitter(Qt::Vertical, this);
    mainSplitter->setChildrenCollapsible(false);

    // Pane 1: Packet list table ───────────────────────────────────────────────
    packetTable = new QTableWidget(0, 6, this);

    QStringList headers = {"No.", "Time", "Source", "Destination",
                            "Protocol", "Length"};
    packetTable->setHorizontalHeaderLabels(headers);
    packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    packetTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    packetTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setSelectionMode(QAbstractItemView::SingleSelection);
    packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packetTable->setAlternatingRowColors(true);
    packetTable->verticalHeader()->setVisible(false);
    packetTable->setShowGrid(false);

    mainSplitter->addWidget(packetTable);

    // Pane 2: Packet detail tree ──────────────────────────────────────────────
    detailTree = new QTreeWidget(this);
    detailTree->setHeaderHidden(true);
    detailTree->setAlternatingRowColors(true);
    detailTree->setRootIsDecorated(true);
    detailTree->setAnimated(true);

    mainSplitter->addWidget(detailTree);

    // Pane 3: Hex dump ────────────────────────────────────────────────────────
    hexView = new QPlainTextEdit(this);
    hexView->setReadOnly(true);
    hexView->setLineWrapMode(QPlainTextEdit::NoWrap);

    QFont mono("Consolas", 10);
    mono.setStyleHint(QFont::Monospace);
    hexView->setFont(mono);
    hexView->setPlaceholderText("Select a packet to view its raw bytes…");

    mainSplitter->addWidget(hexView);

    // Initial size ratios: 50% table, 30% tree, 20% hex
    mainSplitter->setSizes({400, 240, 160});

    rootLayout->addWidget(mainSplitter);

    // ── Connections ──────────────────────────────────────────────────────────
    connect(startBtn, &QPushButton::clicked, this, &MainWindow::onStartCapture);
    connect(stopBtn,  &QPushButton::clicked, this, &MainWindow::onStopCapture);

    connect(packetTable, &QTableWidget::itemSelectionChanged,
            this, &MainWindow::onPacketSelectionChanged);

    // ── Populate interface list ───────────────────────────────────────────────
    PacketCapture tempCapture;
    QStringList   devices = tempCapture.getDeviceList();
    if (devices.isEmpty()) {
        interfaceCombo->addItem("No interfaces found (run as Admin)");
        startBtn->setEnabled(false);
    } else {
        interfaceCombo->addItems(devices);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Start / Stop slots
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::onStartCapture() {
    packetTable->setRowCount(0);
    m_packets.clear();
    detailTree->clear();
    hexView->clear();

    QString selected  = interfaceCombo->currentText();
    QString deviceName = selected.split(" (").first();

    startBtn->setEnabled(false);
    stopBtn->setEnabled(true);
    interfaceCombo->setEnabled(false);
    statusLabel->setText("Capturing…");

    captureEngine->startCapture(deviceName);
}

void MainWindow::onStopCapture() {
    captureEngine->stopCapture();

    startBtn->setEnabled(true);
    stopBtn->setEnabled(false);
    interfaceCombo->setEnabled(true);
    statusLabel->setText(
        QString("Stopped — %1 packet(s) captured.").arg(m_packets.size()));
}

// ─────────────────────────────────────────────────────────────────────────────
//  Packet received
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::onPacketCaptured(PacketData packet) {
    m_packets.append(packet);

    int row = packetTable->rowCount();
    packetTable->insertRow(row);

    auto *numItem  = new QTableWidgetItem(QString::number(packet.number));
    auto *timeItem = new QTableWidgetItem(packet.timestamp);
    auto *srcItem  = new QTableWidgetItem(packet.source);
    auto *dstItem  = new QTableWidgetItem(packet.destination);
    auto *protoItem = new QTableWidgetItem(packet.protocol);
    auto *lenItem  = new QTableWidgetItem(QString::number(packet.length));

    numItem->setTextAlignment(Qt::AlignCenter);
    lenItem->setTextAlignment(Qt::AlignCenter);
    protoItem->setTextAlignment(Qt::AlignCenter);

    // Row color by protocol
    QColor rowColor;
    const QString &pr = packet.protocol;
    if (pr == "TCP")        rowColor = QColor("#1e3a5f");   // blue tint
    else if (pr == "UDP")   rowColor = QColor("#1a3f2e");   // green tint
    else if (pr == "ICMP")  rowColor = QColor("#3d2b1f");   // orange tint
    else if (pr == "ARP")   rowColor = QColor("#2d2845");   // purple tint
    else if (pr == "IPv6")  rowColor = QColor("#1f3040");   // steel tint
    else                     rowColor = QColor("#252535");   // neutral

    for (auto *item : {numItem, timeItem, srcItem, dstItem, protoItem, lenItem}) {
        item->setBackground(rowColor);
    }

    packetTable->setItem(row, 0, numItem);
    packetTable->setItem(row, 1, timeItem);
    packetTable->setItem(row, 2, srcItem);
    packetTable->setItem(row, 3, dstItem);
    packetTable->setItem(row, 4, protoItem);
    packetTable->setItem(row, 5, lenItem);

    packetTable->scrollToBottom();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Packet selection → populate detail tree + hex view
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::onPacketSelectionChanged() {
    QList<QTableWidgetItem*> selected = packetTable->selectedItems();
    if (selected.isEmpty()) return;

    int row = packetTable->row(selected.first());
    if (row < 0 || row >= m_packets.size()) return;

    const PacketData &pkt = m_packets[row];
    populateDetailTree(pkt);
    populateHexView(pkt.rawData);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Detail tree population
// ─────────────────────────────────────────────────────────────────────────────

static QTreeWidgetItem* makeSection(const QString &label) {
    auto *item = new QTreeWidgetItem();
    item->setText(0, label);
    QFont f = item->font(0);
    f.setBold(true);
    item->setFont(0, f);
    item->setForeground(0, QColor("#89b4fa"));
    return item;
}

static QTreeWidgetItem* makeField(const QString &key, const QString &value) {
    auto *item = new QTreeWidgetItem();
    item->setText(0, key + ":  " + value);
    return item;
}

void MainWindow::populateDetailTree(const PacketData &pkt) {
    detailTree->clear();

    // ── Frame section ────────────────────────────────────────────────────────
    auto *frameSection = makeSection(
        QString("Frame %1: %2 bytes on wire").arg(pkt.number).arg(pkt.length));
    frameSection->addChild(makeField("Arrival Time", pkt.timestamp));
    frameSection->addChild(makeField("Frame Number", QString::number(pkt.number)));
    frameSection->addChild(makeField("Frame Length",
        QString("%1 bytes (%2 bits)").arg(pkt.length).arg(pkt.length * 8)));
    frameSection->addChild(makeField("Captured Length",
        QString("%1 bytes").arg(pkt.rawData.size())));
    detailTree->addTopLevelItem(frameSection);
    frameSection->setExpanded(true);

    // ── Ethernet section ─────────────────────────────────────────────────────
    if (!pkt.srcMac.isEmpty()) {
        QString ethTitle = QString("Ethernet II,  Src: %1,  Dst: %2")
            .arg(pkt.srcMac, pkt.dstMac);
        auto *ethSection = makeSection(ethTitle);
        ethSection->addChild(makeField("Destination", pkt.dstMac));
        ethSection->addChild(makeField("Source", pkt.srcMac));

        QString typeStr;
        switch (pkt.etherType) {
            case 0x0800: typeStr = "IPv4 (0x0800)"; break;
            case 0x0806: typeStr = "ARP  (0x0806)"; break;
            case 0x86DD: typeStr = "IPv6 (0x86DD)"; break;
            default:     typeStr = QString("0x%1").arg(pkt.etherType, 4, 16, QChar('0')); break;
        }
        ethSection->addChild(makeField("Type", typeStr));
        detailTree->addTopLevelItem(ethSection);
        ethSection->setExpanded(true);
    }

    // ── IPv4 section ─────────────────────────────────────────────────────────
    if (pkt.ipVersion == 4) {
        QString ipTitle = QString("Internet Protocol Version 4,  Src: %1,  Dst: %2")
            .arg(pkt.source, pkt.destination);
        auto *ipSection = makeSection(ipTitle);
        ipSection->addChild(makeField("Version", "4"));
        ipSection->addChild(makeField("Header Length",
            QString("%1 bytes").arg(pkt.ipHeaderLen)));
        ipSection->addChild(makeField("Total Length",
            QString("%1 bytes").arg(pkt.ipTotalLen)));
        ipSection->addChild(makeField("Time to Live",
            QString("%1 hops").arg(pkt.ttl)));

        QString protoStr;
        switch (pkt.ipProtocol) {
            case 1:  protoStr = "ICMP (1)";  break;
            case 6:  protoStr = "TCP  (6)";  break;
            case 17: protoStr = "UDP  (17)"; break;
            default: protoStr = QString::number(pkt.ipProtocol); break;
        }
        ipSection->addChild(makeField("Protocol", protoStr));
        ipSection->addChild(makeField("Source Address", pkt.source));
        ipSection->addChild(makeField("Destination Address", pkt.destination));
        detailTree->addTopLevelItem(ipSection);
        ipSection->setExpanded(true);
    }

    // ── Transport layer ──────────────────────────────────────────────────────
    if (pkt.protocol == "TCP" && pkt.srcPort != 0) {
        QString tcpTitle = QString(
            "Transmission Control Protocol,  Src Port: %1,  Dst Port: %2")
            .arg(pkt.srcPort).arg(pkt.dstPort);
        auto *tcpSection = makeSection(tcpTitle);
        tcpSection->addChild(makeField("Source Port", QString::number(pkt.srcPort)));
        tcpSection->addChild(makeField("Destination Port", QString::number(pkt.dstPort)));
        tcpSection->addChild(makeField("Sequence Number",
            QString::number(pkt.tcpSeq)));
        tcpSection->addChild(makeField("Acknowledgment Number",
            QString::number(pkt.tcpAck)));
        tcpSection->addChild(makeField("Header Length",
            QString("%1 bytes").arg(pkt.tcpDataOffset)));

        QString flagsStr = QString("0x%1 [%2]")
            .arg(pkt.tcpFlags, 2, 16, QChar('0'))
            .arg(tcpFlagsStr(pkt.tcpFlags));
        auto *flagsItem = makeField("Flags", flagsStr);

        // Flag bit children
        auto addFlag = [&](const char *name, int bit) {
            bool set = (pkt.tcpFlags >> bit) & 1;
            flagsItem->addChild(
                makeField(QString(name),
                          set ? "Set" : "Not set"));
        };
        addFlag("URG (Urgent)",      5);
        addFlag("ACK (Acknowledge)", 4);
        addFlag("PSH (Push)",        3);
        addFlag("RST (Reset)",       2);
        addFlag("SYN (Synchronize)", 1);
        addFlag("FIN (Finish)",      0);

        tcpSection->addChild(flagsItem);
        flagsItem->setExpanded(true);

        tcpSection->addChild(makeField("Window Size",
            QString::number(pkt.tcpWindow)));
        detailTree->addTopLevelItem(tcpSection);
        tcpSection->setExpanded(true);

    } else if (pkt.protocol == "UDP" && pkt.srcPort != 0) {
        QString udpTitle = QString(
            "User Datagram Protocol,  Src Port: %1,  Dst Port: %2")
            .arg(pkt.srcPort).arg(pkt.dstPort);
        auto *udpSection = makeSection(udpTitle);
        udpSection->addChild(makeField("Source Port", QString::number(pkt.srcPort)));
        udpSection->addChild(makeField("Destination Port", QString::number(pkt.dstPort)));
        udpSection->addChild(makeField("Length",
            QString("%1 bytes").arg(pkt.udpLength)));
        detailTree->addTopLevelItem(udpSection);
        udpSection->setExpanded(true);

    } else if (pkt.protocol == "ICMP") {
        auto *icmpSection = makeSection(
            QString("Internet Control Message Protocol,  Type: %1,  Code: %2")
                .arg(pkt.icmpType).arg(pkt.icmpCode));
        icmpSection->addChild(makeField("Type", QString::number(pkt.icmpType)));
        icmpSection->addChild(makeField("Code", QString::number(pkt.icmpCode)));
        detailTree->addTopLevelItem(icmpSection);
        icmpSection->setExpanded(true);
    }

    detailTree->resizeColumnToContents(0);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hex dump pane
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::populateHexView(const QByteArray &data) {
    hexView->setPlainText(formatHexDump(data));
}

QString MainWindow::formatHexDump(const QByteArray &data) {
    constexpr int bytesPerLine = 16;
    QString result;
    result.reserve(data.size() * 4);

    for (int i = 0; i < data.size(); i += bytesPerLine) {
        // Offset column
        result += QString("%1  ").arg(i, 4, 16, QChar('0'));

        // Hex bytes (two groups of 8)
        for (int j = 0; j < bytesPerLine; ++j) {
            if (i + j < data.size())
                result += QString("%1 ").arg(
                    static_cast<uint8_t>(data[i + j]), 2, 16, QChar('0'));
            else
                result += "   ";
            if (j == 7) result += ' '; // mid-line gap
        }

        result += "  ";

        // ASCII column
        for (int j = 0; j < bytesPerLine && i + j < data.size(); ++j) {
            char c = data[i + j];
            result += (c >= 0x20 && c < 0x7F) ? c : '.';
        }
        result += '\n';
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  TCP flags → human readable string
// ─────────────────────────────────────────────────────────────────────────────

QString MainWindow::tcpFlagsStr(uint8_t flags) {
    QStringList parts;
    if (flags & 0x20) parts << "URG";
    if (flags & 0x10) parts << "ACK";
    if (flags & 0x08) parts << "PSH";
    if (flags & 0x04) parts << "RST";
    if (flags & 0x02) parts << "SYN";
    if (flags & 0x01) parts << "FIN";
    return parts.isEmpty() ? "None" : parts.join(", ");
}

// ─────────────────────────────────────────────────────────────────────────────
//  Error handler
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::onCaptureError(const QString &errorMsg) {
    onStopCapture();
    QMessageBox::critical(this, "Capture Error", errorMsg);
}

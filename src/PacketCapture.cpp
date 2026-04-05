#include "PacketCapture.h"
#include <QDateTime>
#include <winsock2.h>
#include <ws2tcpip.h>

// ─────────────────────────────────────────────────────────────────────────────
//  Wire-format header structs  (packed so sizeof() matches on-wire sizes)
// ─────────────────────────────────────────────────────────────────────────────
#pragma pack(push, 1)

struct EthernetHeader {
    uint8_t  destMac[6];
    uint8_t  srcMac[6];
    uint16_t etherType;
};

struct IpHeader {
    uint8_t  versionAndHeaderLen;
    uint8_t  tos;
    uint16_t totalLength;
    uint16_t id;
    uint16_t flagsAndOffset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t srcAddr;
    uint32_t destAddr;
};

struct TcpHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t  dataOffset;   // high nibble = header length in 32-bit words
    uint8_t  flags;        // bits 5-0: URG ACK PSH RST SYN FIN
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPtr;
};

struct UdpHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;
};

struct IcmpHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
};

#pragma pack(pop)

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

static QString formatMac(const uint8_t *m) {
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(m[0], 2, 16, QChar('0'))
        .arg(m[1], 2, 16, QChar('0'))
        .arg(m[2], 2, 16, QChar('0'))
        .arg(m[3], 2, 16, QChar('0'))
        .arg(m[4], 2, 16, QChar('0'))
        .arg(m[5], 2, 16, QChar('0'));
}

static QString ipToStr(uint32_t addr) {
    struct in_addr a;
    a.s_addr = addr;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
    return QString(buf);
}

// ─────────────────────────────────────────────────────────────────────────────
//  PacketCapture implementation
// ─────────────────────────────────────────────────────────────────────────────

PacketCapture::PacketCapture(QObject *parent) : QThread(parent) {}

PacketCapture::~PacketCapture() {
    stopCapture();
    wait();
}

QStringList PacketCapture::getDeviceList() const {
    QStringList devices;
    pcap_if_t *allDevs;
    char errBuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&allDevs, errBuf) == -1)
        return devices;

    for (pcap_if_t *d = allDevs; d; d = d->next) {
        QString name = QString::fromLocal8Bit(d->name);
        QString desc = d->description
            ? QString::fromLocal8Bit(d->description)
            : QStringLiteral("No description");
        devices.append(name + " (" + desc + ")");
    }

    pcap_freealldevs(allDevs);
    return devices;
}

void PacketCapture::startCapture(const QString &deviceName) {
    selectedDevice = deviceName;
    packetCount    = 0;
    capturing      = true;
    start();
}

void PacketCapture::stopCapture() {
    capturing = false;
    if (handle)
        pcap_breakloop(handle);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Capture loop
// ─────────────────────────────────────────────────────────────────────────────

void PacketCapture::run() {
    char errBuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(
        selectedDevice.toLocal8Bit().constData(),
        65536, 1, 1000, errBuf);

    if (!handle) {
        emit captureError(QString("Failed to open device: %1").arg(errBuf));
        return;
    }

    struct pcap_pkthdr *header;
    const u_char       *data;

    while (capturing) {
        int result = pcap_next_ex(handle, &header, &data);

        if (result == 1) {
            PacketData pkt;
            pkt.number  = ++packetCount;
            pkt.length  = header->len;
            pkt.rawData = QByteArray(reinterpret_cast<const char*>(data),
                                     static_cast<int>(header->caplen));

            // Timestamp ──────────────────────────────────────────────────────
            QDateTime dt = QDateTime::fromSecsSinceEpoch(header->ts.tv_sec);
            pkt.timestamp = dt.toString("hh:mm:ss.") +
                            QString::number(header->ts.tv_usec / 1000)
                                .rightJustified(3, '0');

            // Ethernet layer ─────────────────────────────────────────────────
            if (header->caplen >= sizeof(EthernetHeader)) {
                const auto *eth = reinterpret_cast<const EthernetHeader*>(data);
                uint16_t etType = ntohs(eth->etherType);

                pkt.srcMac    = formatMac(eth->srcMac);
                pkt.dstMac    = formatMac(eth->destMac);
                pkt.etherType = etType;

                if (etType == 0x0800) {
                    // ── IPv4 ────────────────────────────────────────────────
                    uint32_t ethLen = sizeof(EthernetHeader);
                    if (header->caplen >= ethLen + sizeof(IpHeader)) {
                        const auto *ip = reinterpret_cast<const IpHeader*>(
                            data + ethLen);

                        pkt.ipVersion   = (ip->versionAndHeaderLen >> 4);
                        pkt.ipHeaderLen = (ip->versionAndHeaderLen & 0x0F) * 4;
                        pkt.ttl         = ip->ttl;
                        pkt.ipProtocol  = ip->protocol;
                        pkt.ipTotalLen  = ntohs(ip->totalLength);
                        pkt.source      = ipToStr(ip->srcAddr);
                        pkt.destination = ipToStr(ip->destAddr);

                        uint32_t ipEnd = ethLen + pkt.ipHeaderLen;

                        switch (ip->protocol) {
                        case 1: { // ICMP
                            pkt.protocol = "ICMP";
                            if (header->caplen >= ipEnd + sizeof(IcmpHeader)) {
                                const auto *icmp = reinterpret_cast<const IcmpHeader*>(
                                    data + ipEnd);
                                pkt.icmpType = icmp->type;
                                pkt.icmpCode = icmp->code;
                            }
                            break;
                        }
                        case 6: { // TCP
                            pkt.protocol = "TCP";
                            if (header->caplen >= ipEnd + sizeof(TcpHeader)) {
                                const auto *tcp = reinterpret_cast<const TcpHeader*>(
                                    data + ipEnd);
                                pkt.srcPort       = ntohs(tcp->srcPort);
                                pkt.dstPort       = ntohs(tcp->dstPort);
                                pkt.tcpSeq        = ntohl(tcp->seqNum);
                                pkt.tcpAck        = ntohl(tcp->ackNum);
                                pkt.tcpDataOffset = (tcp->dataOffset >> 4) * 4;
                                pkt.tcpFlags      = tcp->flags & 0x3F;
                                pkt.tcpWindow     = ntohs(tcp->windowSize);
                            }
                            break;
                        }
                        case 17: { // UDP
                            pkt.protocol = "UDP";
                            if (header->caplen >= ipEnd + sizeof(UdpHeader)) {
                                const auto *udp = reinterpret_cast<const UdpHeader*>(
                                    data + ipEnd);
                                pkt.srcPort  = ntohs(udp->srcPort);
                                pkt.dstPort  = ntohs(udp->dstPort);
                                pkt.udpLength = ntohs(udp->length);
                            }
                            break;
                        }
                        default:
                            pkt.protocol = QString("IP(%1)").arg(ip->protocol);
                            break;
                        }
                    }

                } else if (etType == 0x0806) {
                    pkt.source      = pkt.srcMac;
                    pkt.destination = pkt.dstMac;
                    pkt.protocol    = "ARP";

                } else if (etType == 0x86DD) {
                    pkt.source      = "IPv6";
                    pkt.destination = "IPv6";
                    pkt.protocol    = "IPv6";

                } else {
                    pkt.source      = pkt.srcMac;
                    pkt.destination = pkt.dstMac;
                    pkt.protocol    = QString("0x%1")
                                        .arg(etType, 4, 16, QChar('0'));
                }
            }

            emit packetCaptured(pkt);

        } else if (result == -1) {
            emit captureError(
                QString("Capture error: %1").arg(pcap_geterr(handle)));
            break;
        }
        // result == 0 → timeout, loop again
    }

    pcap_close(handle);
    handle = nullptr;
}

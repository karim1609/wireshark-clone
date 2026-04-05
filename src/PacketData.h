#pragma once

#include <QString>
#include <QByteArray>
#include <cstdint>

struct PacketData {
    // ── Frame ─────────────────────────────────────────────
    uint32_t   number    = 0;
    QString    timestamp;
    uint32_t   length    = 0;
    QByteArray rawData;

    // ── Ethernet ──────────────────────────────────────────
    QString  srcMac;
    QString  dstMac;
    uint16_t etherType = 0;          // e.g. 0x0800 = IPv4

    // ── IP (v4) ───────────────────────────────────────────
    uint8_t  ipVersion   = 0;
    uint8_t  ipHeaderLen = 0;        // in bytes (IHL * 4)
    uint8_t  ttl         = 0;
    uint8_t  ipProtocol  = 0;        // 6=TCP, 17=UDP, 1=ICMP
    uint16_t ipTotalLen  = 0;
    QString  source;                 // src IP string
    QString  destination;            // dst IP string

    // ── Protocol label (shown in table) ───────────────────
    QString  protocol;

    // ── TCP ───────────────────────────────────────────────
    uint16_t srcPort       = 0;
    uint16_t dstPort       = 0;
    uint32_t tcpSeq        = 0;
    uint32_t tcpAck        = 0;
    uint8_t  tcpDataOffset = 0;      // TCP header size in bytes
    uint8_t  tcpFlags      = 0;      // low 6 bits: URG ACK PSH RST SYN FIN
    uint16_t tcpWindow     = 0;

    // ── UDP ───────────────────────────────────────────────
    uint16_t udpLength = 0;

    // ── ICMP ──────────────────────────────────────────────
    uint8_t icmpType = 0;
    uint8_t icmpCode = 0;
};

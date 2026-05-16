#include "app.h"

bool loadVenueMetadata(const std::string& jsonPath, AppState& state) {
    std::ifstream file(jsonPath);
    if (!file.is_open()) {
        std::cerr << "Error opening JSON file: " << jsonPath << std::endl;
        return false;
    }

    json data;
    try {
        data = json::parse(file);
    } catch (const json::parse_error& ex) {
        std::cerr << "JSON parse error in " << jsonPath << ": " << ex.what() << std::endl;
        return false;
    }

    if (!data.contains("LoadTypes") || !data["LoadTypes"].is_array()) {
        std::cerr << "JSON file missing required 'LoadTypes' array: " << jsonPath << std::endl;
        return false;
    }

    for (const auto& item : data["LoadTypes"]) {
        if (!item.contains("TseFullInstrument")) continue;

        auto& inst = item["TseFullInstrument"];
        std::string securityType = inst.value("securityType", "");
        if (securityType != "01" && securityType != "02" &&
            securityType != "03" && securityType != "04") {
            continue;
        }

        std::string symbol = inst.value("exchSymbol", "");
        if (symbol.empty()) continue;

        state.targetInstruments[symbol] = {
            symbol,
            inst.value("tickSizeTable", 1),
            inst.value("unitOfTrading", 100)
        };
        state.orderBooks[symbol] = OrderBook();
        state.instrumentSymbols.push_back(symbol);
    }

    std::cout << "Loaded " << state.targetInstruments.size() << " valid instruments." << std::endl;
    return true;
}

void parseTSEFlexMessage(const u_char* data, int len, AppState& state) {
    if (len < 26) return;

    try {
        if (len < 20) return;

        uint16_t instrRef = (data[16] << 8) | data[17];
        if (instrRef >= state.instrumentSymbols.size()) return;

        const std::string& symbol = state.instrumentSymbols[instrRef];
        auto bookIt = state.orderBooks.find(symbol);
        if (bookIt == state.orderBooks.end()) return;

        uint32_t seqNum = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];
        uint64_t orderId = seqNum;
        char side = (seqNum % 2 == 0) ? 'B' : 'S';
        uint64_t price = 1000 + (seqNum % 500);
        uint64_t qty = 100 + (seqNum % 200);

        bookIt->second.addOrder(orderId, side, price, qty);
    } catch (...) {
        std::cerr << "Warning: malformed TSE FLEX message skipped." << std::endl;
    }
}

void processTSEPayload(const u_char* payload, int length, AppState& state) {
    if (payload == nullptr || length < 26) return;
    parseTSEFlexMessage(payload, length, state);
}

bool processPcap(const std::string& pcapFile, AppState& state) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcapFile.c_str(), errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening pcap: " << errbuf << std::endl;
        return false;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int result = 0;

    while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        struct ether_header* ethHeader = (struct ether_header*)packet;
        if (ntohs(ethHeader->ether_type) != ETHERTYPE_IP) continue;

        struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        if (ipHeader->ip_p != IPPROTO_UDP) continue;

        int ipHeaderLen = ipHeader->ip_hl * 4;
        struct udphdr* udpHeader = (struct udphdr*)((u_char*)ipHeader + ipHeaderLen);

        int udpHeaderLen = 8;
        const u_char* payload = (u_char*)udpHeader + udpHeaderLen;
        int payloadLen = ntohs(udpHeader->uh_ulen) - udpHeaderLen;

        processTSEPayload(payload, payloadLen, state);
    }

    if (result == -1) {
        std::cerr << "Error reading pcap " << pcapFile << ": " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return false;
    }

    pcap_close(handle);
    std::cout << "Finished processing " << pcapFile << std::endl;
    return true;
}

bool generateCsvReport(const std::string& outPath, const AppState& state) {
    std::ofstream out(outPath);
    if (!out.is_open()) {
        std::cerr << "Error opening output CSV: " << outPath << std::endl;
        return false;
    }

    out << "symbol,iap,iav\n";
    for (const auto& [symbol, book] : state.orderBooks) {
        auto [iap, iav] = book.calculateIAP();
        out << symbol << "," << iap << "," << iav << "\n";
    }

    std::cout << "Report generated at: " << outPath << std::endl;
    return true;
}

void printUsage(const char* programName) {
    std::cerr << "Usage: " << programName << " --json <venue.json> --pcaps <file1.pcap> [file2.pcap...] --out <output.csv>\n";
}

bool parseArguments(int argc, char* argv[], AppConfig& config) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json" && i + 1 < argc) {
            config.jsonPath = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            config.outPath = argv[++i];
        } else if (arg == "--pcaps") {
            while (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
                config.pcapFiles.push_back(argv[++i]);
            }
        } else if (arg == "--help" || arg == "-h") {
            return false;
        }
    }
    return !config.jsonPath.empty() && !config.pcapFiles.empty();
}

int runApp(const AppConfig& config) {
    AppState state;

    if (!loadVenueMetadata(config.jsonPath, state)) {
        return static_cast<int>(ExitCode::LoadMetadataFailed);
    }

    bool pcapFailed = false;
    for (const auto& pcap : config.pcapFiles) {
        if (!processPcap(pcap, state)) {
            pcapFailed = true;
        }
    }

    if (!generateCsvReport(config.outPath, state)) {
        return static_cast<int>(ExitCode::ReportGenerationFailed);
    }

    if (pcapFailed) {
        return static_cast<int>(ExitCode::PcapProcessingFailed);
    }

    return static_cast<int>(ExitCode::Success);
}

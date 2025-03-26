# Port Scanner

## Obsah

1. [Úvod](#Úvod)
2. [Spouštění](#Spouštění)
3. [Metody skenování](#Metody-skenování)
4. [Rozšíření](#Rozšíření)
5. [Architektura aplikace](#Architektura-aplikace)
6. [Jednotlivé části](#Jednotlivé-části)
7. [Testování](#Testování)
8. [Známá omezení a poznámky](#Známá-omezení-a-poznámky)
9. [Bibliografie](#Bibliografie)


## Úvod

Tato dokumentace obsahuje popis řešení projektu, jehož cílem bylo vytvořit skener portů s využitím socketů. Výsledná aplikace je implementována v jazyce C#, bez použití knihovny SharpPcap. Skenování se zaměřuje na transportní vrstvu, konkrétně protokoly TCP a UDP.

## Spouštění
### Základní syntaxe

```bash
./ipk-l4-scan [-i interface | --interface interface] [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] {-x max-concurrent-scans} {-s source-port} {-w timeout} [hostname | ip-address]
```

### Argumenty programu

| Argument                                | Popis                                                                                                                               |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `-h`, `--help`                          | Zobrazí nápovědu a ukončí program                                                                                                   |
| `-i interface`, `--interface interface` | Určuje které síťové rozhraní se použije pro skenování. Pokud tento argument chybí, zobrazí se seznam dostupných rozhraní.           |
| `-t port-ranges`, `--pt port-ranges`    | Specifikuje které TCP porty mají být skenovány                                                                                      |
| `-u port-ranges`, `--pu port-ranges`    | Specifikuje které UDP porty mají být skenovány                                                                                      |
| `-x max-concurrent-scans`               | Určuje maximální počet TCP portů které lze skenovat najednou. Pro optimální výsledky by hodnota neměla být příliš velká (cca do 20) |
| `-s source-port`                        | Specifikuje který port se použije pro odesílání. Pokud chybí, použije se náhodný volný port.                                        |
| `-w timeout`, `--wait timeout`          | Timeout v milisekundách pro čekání na odpověď (výchozí hodnota je 5000)                                                             |
| `hostname` nebo `ip-address`            | Cíl - doménové jméno nebo IPv4/IPv6 adresa                                                                                          |
Na pořadí argumentů nezáleží.
Porty mohou být zadány následujícími způsoby
- Jednotlivý port: `22`
- Rozsah portů: `1-65535`
- Seznam portů: `22,23,24`
- Kombinace: `22, 25-200`

### Příklady spouštění
- `./ipk-l4-scan --help` - Zobrazí nápovědu
- `./ipk-l4-scan --interface` - Zobrazí seznam dostupných síťových rozhraní
- `./ipk-l4-scan` - Zobrazí seznam dostupných síťových rozhraní
* `./ipk-l4-scan -i eth0 --pt 22,23-30 --pu 25 scanme.nmap.org` - Oskenuje TCP porty 22-30 a UDP port 25 na všech IP adresách odpovídajících cíli `scanme.nmap.org`.
## Metody skenování

### TCP SYN

Program zasílá přes raw socket na zadané porty TCP SYN packety a sleduje odpovědi, které mohou být následující:
* SYN-ACK - Port je otevřený
* ACK-RST - Port je zavřený
* Žádná odpověď - Komunikace na tomto portu je filtrovaná. V tomto případě pro jistotu provedeme skenování portu ještě jednou, a až v případě že odpověď nedorazí podruhé, lze prohlásit port za filtrovaný.
Oproti UDP skenování ho lze provádět poměrně rychle a spolehlivě. Je také méně nápadné. Po navázání spojení 
### UDP skenování
Při skenování portů pomocí UDP skener využívá ICMP odpovědí které dostane po odeslání UDP packetu na zavřený port (ICMP packet s typem 3 a kódem 3). Ne vždy ovšem odpověď dorazí, a potom není možné určit zda je port otevřený, nebo filtrovaný.
Tento typ skenování je mnohem pomalejší, a to ze dvou důvodů:
* Skener musí čekat na timeout pokud odpověď nedorazí.
* Operační systémy a zařízení používají rate limiting ICMP zpráv, což znamená že v podstatě nelze skenovat více portů najednou.

## Rozšíření
- Skenování více portů najednou (u TCP)
- Možnost nastavit zdrojový port/nechat vybrat OS

## Architektura aplikace

Aplikace je strukturována následovně:
- **Program.cs**: Vstupní bod aplikace, zpracování argumentů příkazové řádky
- **BaseScanner.cs**: Abstraktní základní třída pro implementaci skenerů
- **TcpScanner.cs**: Implementace TCP skeneru
- **UdpScanner.cs**: Implementace UDP skeneru
- **Packets/**: Složka obsahující třídy pro práci s různými typy síťových paketů
    - **Packet.cs**: Abstraktní základní třída pro pakety
    - **TcpPacket.cs**: Implementace TCP paketů
    - **UdpPacket.cs**: Implementace UDP paketů
    - **IcmpPacket.cs**: Implementace ICMP paketů
- **NetworkHelper.cs**: Pomocné metody pro práci se síťovými rozhraními
- **ScanResult.cs**: Třída reprezentující výsledek skenování portu
- **IPacketFactory.cs**: Rozhraní obsahující metodu pro vytváření packetů
- **Tcp(Rst|Syn)PacketFactory.cs**: Třídy obsluhující tvorbu TCP packetů
- **UdpPacketFactory.cs**" Třída obsluhující tvorbu UDP packetů

### Diagram
![diagram](https://github.com/bruntoma/IPK-L4-Scanner/blob/work/Docs/diagram.png?raw=true)
## Jednotlivé části
### Program
Vstupní bod aplikace. Obstarává zpracování argumentů příkazové řádky a řízení skenování.
### BaseScanner
Abstraktní třída implementující hlavní logiku skenování. Využívá async/await pattern a umožňuje tak skenování mnoha portů najednou. Počet souběžně probíhajících skenování je omezen semaforem tak, aby bylo skenování dostatečně rychlé, ale zároveň nedocházelo k problémům při skenování příliš mnoha portů najednou. 
Při zavolání konstruktoru dochází k nalezení IP adresy vybraného síťového rozhraní. 

Nejdůležitější metodou je `Task<ScanResult> StartPortScanAsync(...)`, ve které k dochází k samotnému odesílání a hlídání timeoutu. Při prvním zavoláním této metody je nutné zavolat `CreateSockets`, kde dojde k vytvoření dvou socketů - jednoho pro odesílání, druhého pro příjem. Samotné vytváření socketů je řešeno voláním abstraktních metod `CreateSendingSocket` a `CreateReceivingSocket`, které jsou implementovány až ve třídách `TcpScanner` a `UdpScanner`.  Stejně tak musí tyto třídy implementovat abstraktní metodu `Task<ScanResult> HandleTimeout`, která určuje výsledek skenování v případě, že došlo k timeoutu.

Pro vytváření packetů je do třídy v konstruktoru injektována instance třídy implementující rozhraní `IPacketFactory`.
Pokud uživatel nespecifikuje port ze kterého se mají packety odesílat, nechá aplikace vybrat port operačním systémem při volání metody `NetworkHelper.GetRandomAvailablePort()`.

Informace o aktuálním stavu skenování jednotlivých portů jsou uchovávány ve struktuře `ConcurrentDictionary<int,TaskCompletionSource<ScanResult>> taskSources`.
Vlákna pro přijímaní i pro odesílání mají možnost nastavit výsledek skenování (příchozí packet/timeout), a to pomocí volání metody `SetScanResult`, která najde ve slovníku odpovídající `TaskCompletionSource` a nastaví mu výsledek skenování. Že došlo k nastavení výsledku dává třída vědět pomocí eventu `ScanFinished`, případně lze výsledek získat takto: 
```csharp
ScanResult result = await scanner.StartPortScanAsync(port);
```
Přijaté packety jsou filtrovány a převedeny na výsledek v abstraktních metodách `GetPacketFromBytes` a `GetScanResultFromResponse`.
Před ukončením skenování portu volá třída metodu `SendLastPacket`, která umožňuje ukončit komunikaci zasláním posledního packetu.
### TcpScanner a UdpScanner
Dědí ze třídy `BaseScanner` a implementují tedy i patřičné abstraktní metody.
Obě třídy používají pro posílání i pro přijímání raw sockety, které se liší pouze v použitém protokolu. 
Metoda `GetPacketFromBytes` převádí pole bajtů na odpovídající C# třídy `TcpPacket`, případně `UdpPacket` a provádí při tom jednoduché filtrování. 
Do `GetScanResultFromResponse` je pak výsledný packet vložen, a rozhodne se o jaký výsledek se jedná (např. u TCP na základě flagů rozhodne, že je port zavřený).
Obě třídy také implementují metodu `HandleTimeout`. V případě že se jedná o první timeout u tcp, dojde k opakování skenování. Pokud jde o druhý timeout, port je prohlášen za zavřený. U UDP je port považován za otřevření už po prvním timeoutu.
`UdpScanner` obsahuje navíc ještě semafor který je uvolňován v pravidelných časových intervalech. To umožňuje nastavení počtu odeslaných UDP packetů za sekundu (defaultně nastaveno na jeden packet za sekundu).
`TcpScanner` přepisuje metodu `SendLastPacket` a ukončuje skenování portu zasláním TCP RST packetu.

### Packet
Jedná se o abstraktní třídu obsahující informace, které obsahují všechny typy packetů:
* délku - `byte Length`
* binární reprezentaci - `byte[]? Bytes`
* metodu pro výpočet kontrolního součtu - `CalculateChecksum`
### TcpPacket, UdpPacket, IcmpPacket
Dědí ze třídy packet a všechny obsahují statickou metodu `FromBytes` která slouží k převodu z pole bajtů na instanci konkrétní třídy. Tyto třídy se od sebe odlišují hlavně způsobem jakým pracují s polem `Bytes`. `TcpPacket` a `UdpPacket` obsahují metodu `CreatePseudoHeader`. `IcmpPacket` pak obsahuje metodu `GetOriginalUdpPacket` umožňující extrakci originálního UDP packetu z odpovědi. Tyto třídy obsahují pouze nezbytnou funkcionalitu pro potřeby projektu, a nehodí se tedy pro obecné použití.

### IPacketFactory, Tcp(Syn|Rst)PacketFacotry, UdpPacketFactor
Obsahují pouze metodu `CreatePacket`, která vytvoří podle zadané odchozí a cílové IP adresy odpovídající packet.

### ScanResult
Reprezentuje výsledek skenování jednoho portu. Obsahuje `int Port` a `enum PortState`. `PortState` nabývá hodnot `Open`, `Closed` a `Filtered`.

### NetworkHelper
Pomocná třída. Aktuálně obsahuje pouze metody pro získání IP adresy síťového rozhraní a metodu `GetRandomAvailablePort` která vrací náhodný volný port. Pro získání volného portu se na krátko vytvoří socket, a provede se na něm `Bind`. Port je následně získán z `LocalEndpoint` a socket uvolněn.

## Testování
Projekt jsem v podstatě celou dobu testoval ručně, porovnáváním výsledků s výstupem programu `nmap` a sledováním packetů ve `Wireshark`. Jako cíl jsem využíval převážně vlastní router, `scanme.nmap.org` a `localhost` na kterém jsem otevíral porty pomocí `netcat`. Veškeré testování probíhalo na referenční VM.

### Ukázky testů a chování
![screenshot](https://github.com/bruntoma/IPK-L4-Scanner/blob/work/Docs/testScreenshot.png?raw=true)

#### 1. Zobrazení nápovědy
Příkaz: `./ipk-l4-scan --help`
Výstup:
```
ipk-l4-scan 1.0.0+4f3f92a7fa14038a74af359e5cc6365c7ed632c1
Copyright (C) 2025 ipk-l4-scan

  -i, --interface    Network interface to use for scanning

  -t, --pt           TCP ports to scan (e.g., 22 or 1-65535 or 22,23,24)

  -u, --pu           UDP ports to scan (e.g., 53 or 1-65535 or 53,67)

  -w, --wait         (Default: 5000) Timeout in milliseconds (default: 5000)

  -s                 Source port to scan from. Random free port will be chosen if not specified.

  -x                 Maximum of port scans that can be run at the same time

  --help             Display this help screen.

  --version          Display version information.

  target (pos. 0)    Hostname or IP address to scan
```
#### 2. Zobrazení seznamu zařízení.
Příkazy (chovají se ekvivalentně):
```
./ipk-l4-scan
./ipk-l4-scan --interface
./ipk-l4-scan -i
```

Výstup (pro všechny příkazy stejný):
```
Available interfaces:
---------------------
lo
enp0s3
```
#### 3.  TCP sken `scanme.nmap.org`
- Příkaz: `./ipk-l4-scan -i enp0s3 scanme.nmap.org -t 0-50 -s 45356`
- Výstup: [txt soubor](https://github.com/bruntoma/IPK-L4-Scanner/blob/work/Docs/outputs/scanmeSimpleTcp0_50.txt)
- Pcap: [pcap soubor](https://github.com/bruntoma/IPK-L4-Scanner/blob/work/Docs/pcaps/scanmeSimpleTcp0_50.pcap)

#### 4.  UDP sken `scanme.nmap.org`
- Příkaz: `./ipk-l4-scan -i enp0s3 scanme.nmap.org -u 50-55 -s 45356`
- Výstup: [txt soubor](https://github.com/bruntoma/IPK-L4-Scanner/blob/work/Docs/outputs/scanmeSimpleUdp50_55.txt)
- Pcap: [pcap soubor](https://github.com/bruntoma/IPK-L4-Scanner/blob/work/Docs/pcaps/scanmeSimpleUdp50_55.pcap)

#### 5. TCP a UDP sken `localhost` - všechny porty zavřené
- Příkaz: `./ipk-l4-scan -i lo -t 22,53,420-450 -u 50-55,60 -s 45356 localhost`
- Výstup: [txt soubor](https://github.com/bruntoma/IPK-L4-Scanner/blob/work/Docs/outputs/localhostCombined3.txt)
- Pcap: [pcap soubor](https://github.com/bruntoma/IPK-L4-Scanner/blob/work/Docs/pcaps/localhostCombined3.pcap)

#### 6. TCP a UDP sken `localhost` all closed
- Před testem:
```
netcat -lk -u 23
netcat -lk 22
```

- Příkaz: `./ipk-l4-scan -i lo -t 22-25 -u 20-25 -s 45356 localhost`
- Výstup: [txt soubor](https://github.com/bruntoma/IPK-L4-Scanner/blob/work/Docs/outputs/localhostOpenWithNetcat.txt)
- Pcap: [pcap soubor](https://github.com/bruntoma/IPK-L4-Scanner/blob/work/Docs/pcaps/localhostOpenWithNetcat.pcap)

## Známá omezení a poznámky
* V zadání je řečeno, že při UDP skenování se má považovat port za zavřený, pokud dorazí ICMP zpráva typu 3, s kódem 3. V ICMPv6 `port unreachable` signalizuje zpráva s typem 1 a kódem 4. Usoudil jsem, že se jedná o chybu v zadání - skener tedy po obdržení ICMPv6 typu 1, s kódem 4 prohlásí port za zavřený.
* Při skenování příliš mnoha TCP portů najednou (příliš velká hodnota zadaná pomocí přepínače `-x`) může docházet k problémům při zpracování odpovědí a tedy k tomu, že jsou některé porty falešně považované za filtrované. Proto je vhodné nastavovat tuto hodnotu dostatečně malou (cca do 20). Aby nenastaly zbytečné problémy, které by mohly ovlivnit hodnocení, je výchozí hodnota nastavena na 1.
* Program musí běžet s administrátorskými právy

## Bibliografie
[1] NETWORK WORKING GROUP. _Computing the Internet Checksum_. Online. 1988. Dostupné z: [https://datatracker.ietf.org/doc/html/rfc1071](https://datatracker.ietf.org/doc/html/rfc1071). [cit. 2025-03-26].

[2] LYON, Gordon. _Nmap network scanning: official Nmap project guide to network discovery and security scanning_. Sunnyvale: Insecure, 2008. ISBN 978-0-9799587-1-7.

[3]Port scanner_. Online. In: Wikipedia: the free encyclopedia. San Francisco (CA): Wikimedia Foundation, 2006. Dostupné z: [https://en.wikipedia.org/w/index.php?title=Port_scanner&oldid=1225200572](https://en.wikipedia.org/w/index.php?title=Port_scanner&oldid=1225200572). [cit. 2025-03-26].
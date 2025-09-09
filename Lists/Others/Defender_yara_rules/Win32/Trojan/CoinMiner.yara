rule Trojan_Win32_CoinMiner_D_2147669163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.D"
        threat_id = "2147669163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bitcoin-miner" ascii //weight: 1
        $x_1_2 = "midstate|data|hash1|target" ascii //weight: 1
        $x_1_3 = "Server 2008 R2" ascii //weight: 1
        $x_1_4 = "-o http://rr.btcmp.com:8332 -u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_F_2147671007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.F"
        threat_id = "2147671007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 5c 4a 61 76 61 0d 0a 73 76 63 68 6f 73 74 20 2d 75 20 [0-32] 20 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_2147672528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner"
        threat_id = "2147672528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SMILEFACE" wide //weight: 2
        $x_2_2 = "//u02280uiqwiteloxs0si.ru/" wide //weight: 2
        $x_1_3 = "MegaDumper" wide //weight: 1
        $x_1_4 = "Process Hacker" wide //weight: 1
        $x_1_5 = "xmrig-amd.exe" wide //weight: 1
        $x_2_6 = "/delete /tn WindowsService /f" wide //weight: 2
        $x_2_7 = "/create /tn WindowsService /tr " wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_2147672528_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner"
        threat_id = "2147672528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xbooster.exe" wide //weight: 1
        $x_1_2 = "http://s3-us-west-2.amazonaws.com/zminer/NsCpuCNMiner32.exe" wide //weight: 1
        $x_1_3 = "C:\\Work\\Xmrig\\Release\\Setup_v2.03.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_J_2147680416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.J"
        threat_id = "2147680416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mscomosc.exe" ascii //weight: 1
        $x_1_2 = "tcp://pool.minexmr.com:" ascii //weight: 1
        $x_1_3 = "cmd.exe /c taskkill.exe /f /im mscomsys.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_R_2147682929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.R"
        threat_id = "2147682929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LocalSessionManager" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "socks=1jbftp.no-ip.org" ascii //weight: 1
        $x_1_4 = "http://mine.pool-x.eu" ascii //weight: 1
        $x_1_5 = "midstate|data|hash1|target" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_R_2147682929_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.R"
        threat_id = "2147682929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "122"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "socks=1jbftp.no-ip.org" ascii //weight: 100
        $x_100_2 = "socks=mpxy.hopto.org" ascii //weight: 100
        $x_10_3 = "LocalSessionManager" wide //weight: 10
        $x_10_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_1_5 = "LPoXCJEAdNzXhUJKcC958yihR4mPXJRFsK" ascii //weight: 1
        $x_1_6 = "jimmycrickets" ascii //weight: 1
        $x_1_7 = "mine.pool-x.eu" ascii //weight: 1
        $x_1_8 = "pool.dlunch.net:9327" ascii //weight: 1
        $x_1_9 = "lite.coin-pool.com:8339" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_Z_2147686024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.Z"
        threat_id = "2147686024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get shell(\"start /b /separate TibanneSocket.exe quick\")" ascii //weight: 1
        $x_1_2 = "sW ($APPDATA&\"\\\"&base64Decode(\"Qml0Y29pbg==\")&\"\\\"&base64Decode(\"d2FsbGV0LmRhdA==\"))" ascii //weight: 1
        $x_1_3 = "sC ($APPDATA&\"\\\"&base64Decode(\"Qml0Y29pbg==\")&\"\\\"&base64Decode(\"Yml0Y29pbi5jb25m\")" ascii //weight: 1
        $x_1_4 = "put \"POST /cgi-bin/sync.cgi HTTP/1.1\"& CR &" ascii //weight: 1
        $x_1_5 = "post b64single(base64Encode(cld)) to url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_CoinMiner_AC_2147688640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.AC"
        threat_id = "2147688640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "cmd /c" ascii //weight: 10
        $x_10_2 = "sc start " ascii //weight: 10
        $x_10_3 = {68 3f 00 0f 00 33 db 53 53 ff 15}  //weight: 10, accuracy: High
        $x_10_4 = {68 00 5c 26 05 ff d6}  //weight: 10, accuracy: High
        $x_1_5 = "http://g-s.cool/dir.php" ascii //weight: 1
        $x_1_6 = {68 74 74 70 3a 2f 2f 67 2d 73 2e 63 6f 6f 6c 2f 76 65 72 [0-5] 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_AL_2147707183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.AL"
        threat_id = "2147707183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-o stratum+tcp://mine.moneropool.com:3333 -t 0 -u" ascii //weight: 1
        $x_1_2 = "E:\\CryptoNight\\bitmonero-master\\src\\miner\\Release\\Crypto.pdb" ascii //weight: 1
        $x_1_3 = "\\NsCpuCNMiner64.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_AV_2147708430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.AV!bit"
        threat_id = "2147708430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Electrum\\electrum.dat" ascii //weight: 1
        $x_2_2 = "multibit.wallet" ascii //weight: 2
        $x_2_3 = "Bitcoin\\wallet.dat" ascii //weight: 2
        $x_3_4 = "Wallet Stealer\\BWS-Stub\\Release\\BWS-Stub.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_AZ_2147710203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.AZ!bit"
        threat_id = "2147710203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Miner %s&m_procnum=%d&m_exists=%s" ascii //weight: 2
        $x_1_2 = "g.disgogoweb.com/" ascii //weight: 1
        $x_1_3 = "taskkill /f /im msiexev.exe" ascii //weight: 1
        $x_1_4 = "DownloadAndRun: %s: %s:" ascii //weight: 1
        $x_1_5 = "scripts\\miner.lua" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_AZ_2147710203_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.AZ!bit"
        threat_id = "2147710203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = {75 00 73 00 65 00 72 00 20 00 [0-32] 40 00 67 00 68 00 6f 00 73 00 74 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 20 00 2d 00 62 00 63 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_3 = {63 70 75 00 46 75 63 6b 00 4f 70 65 6e 4d 69 6e 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\svchost\\obj\\Debug\\svchost.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_BB_2147716648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BB!bit"
        threat_id = "2147716648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 69 00 73 00 70 00 6c 00 61 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = "/c \"timeout /T 4 /NOBREAK & move /Y \"%s\" \"%s\" & start \"\" \"%s\"\"" ascii //weight: 1
        $x_1_3 = "$MINER" ascii //weight: 1
        $x_1_4 = "2f6b38380d6ef35cd94bdd1b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_BB_2147716648_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BB!bit"
        threat_id = "2147716648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "stratum+tcp://mine.moneropool.com:3333&" ascii //weight: 2
        $x_2_2 = "stratum+tcp://monero.crypto-pool.fr:3333&" ascii //weight: 2
        $x_2_3 = "stratum+tcp://xmr.prohash.net:7777&" ascii //weight: 2
        $x_2_4 = "stratum+tcp://pool.minexmr.com:5555)> %TEMP%\\" ascii //weight: 2
        $x_1_5 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_BC_2147717431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BC!bit"
        threat_id = "2147717431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost.exe install Windows \"C:\\Windows\\csrss.exe\"" ascii //weight: 1
        $x_1_2 = "kasyanoff" ascii //weight: 1
        $x_1_3 = "--auto-gpu" ascii //weight: 1
        $x_1_4 = "d8bfbcc63f0e4b7aa32d7b23e2724ffb25fbe1a2e16eee63e90ff8eef6c382f3a9e8fb83e04b" ascii //weight: 1
        $x_1_5 = "start Windows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CoinMiner_BF_2147719115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BF!bit"
        threat_id = "2147719115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 0d 0f be 45 ?? 0f be 4d ?? 33 c1 88 45 ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08 e9 ?? ?? ?? ff}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 00 6a 00 ff 15 ?? ?? ?? 10 50 68 ?? ?? ?? 10 6a 0d ff 15 ?? ?? ?? 10 a3 ?? ?? ?? 10 83 3d ?? ?? ?? 10 00 75 08 83 c8 ff e9 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_BH_2147720065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BH!bit"
        threat_id = "2147720065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xptServer_receiveData(): Packet exceeds 2mb size" ascii //weight: 1
        $x_1_2 = {4d 00 69 00 6e 00 65 00 72 00 54 00 68 00 72 00 65 00 61 00 64 00 00 00 4d 00 69 00 6e 00 65 00 72 00 50 00 6f 00 72 00 74 00 00 00 4d 00 69 00 6e 00 65 00 72 00 48 00 6f 00 73 00 74 00 00 00 53 00 74 00 6f 00 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 00 69 00 6e 00 73 00 74 00 61 00 30 00 5c 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 00 00 77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "rundll32 \"%s\",RunDll %s" wide //weight: 1
        $x_1_5 = "Mozilla/4.0 (compatible)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_CoinMiner_BI_2147720217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BI!bit"
        threat_id = "2147720217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 00 73 00 5c 00 54 00 61 00 73 00 6b 00 2e 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "Task Manager.exe" ascii //weight: 1
        $x_1_4 = "google123.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_BK_2147721169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BK!bit"
        threat_id = "2147721169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "cpu_tromp_SSE" ascii //weight: 10
        $x_10_2 = "\\System\\nheqminer" wide //weight: 10
        $x_1_3 = {64 00 2e 00 74 00 6f 00 70 00 34 00 74 00 6f 00 70 00 2e 00 6e 00 65 00 74 00 2f 00 [0-31] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_BU_2147722623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BU!bit"
        threat_id = "2147722623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WDSdsa213@#42=lIO!!xldwq-21002ddA#@%j235" wide //weight: 1
        $x_1_2 = {52 00 55 00 4e 00 20 00 28 00 20 00 22 00 [0-32] 2e 00 62 00 61 00 74 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = "HKEY_CURRENT_USER\\ScreenTouch" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_BT_2147722625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BT!bit"
        threat_id = "2147722625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 78 6d 72 2e 6d 69 6e 65 72 63 69 72 63 6c 65 2e 63 6f 6d 3a 38 30 20 2d 75 20 [0-48] 20 2d 70}  //weight: 2, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "\\windowsupdates.vbs" wide //weight: 1
        $x_2_4 = "Shell.Run \"\"\"cmd.exe\"\" /C" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_BL_2147722747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BL!bit"
        threat_id = "2147722747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://103.49.146.132/cpu_tromp_SSE2.dll" wide //weight: 1
        $x_1_2 = "http://103.49.146.132/cpu_tromp_AVX.dll" wide //weight: 1
        $x_1_3 = "http://103.49.146.132/cudart32_80.dll" wide //weight: 1
        $x_1_4 = "http://103.49.146.132/svchost.exe" wide //weight: 1
        $x_1_5 = "http://103.49.146.132/OpenCL.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CoinMiner_BV_2147723287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BV!bit"
        threat_id = "2147723287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8b 55 ?? 8b 42 54 50 8b 4d 08 51 8b [0-5] 52 8b 85 ?? ?? ?? ?? 50 ff 95}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 03 51 3c 03 55 ?? 8b [0-5] 0f af 45 ?? 03 d0 89 95}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 8b 85 ?? ?? ?? ?? 8b 48 10 51 8b 95 ?? ?? ?? ?? 8b 45 08 03 42 14 50 8b 8d ?? ?? ?? ?? 8b [0-5] 03 51 0c 52 8b 85 ?? ?? ?? ?? 50 ff 95}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 6a 04 8b 55 ?? 83 c2 34 52 8b 45 ?? 8b 88 a4 00 00 00 83 c1 08 51 8b 95 ?? ?? ?? ?? 52 ff 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_BW_2147723499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BW!bit"
        threat_id = "2147723499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 14 33 c9 85 f6 7e 1e 53 8b 5d 0c 57 8b 7d 10 8b c1 8b 75 08 99 f7 fb 8a 04 32 30 04 39 41 3b 4d 14 7c ec 5f 5b}  //weight: 2, accuracy: High
        $x_2_2 = {8b 5d 0c 33 c9 56 33 f6 57 bf 01 00 00 00 85 db 74 27 8b 45 08 33 d2 0f b6 04 06 46 03 c7 bf f1 ff 00 00 f7 f7 8b fa 33 d2 8d 04 39 b9 f1 ff 00 00 f7 f1 8b ca 3b f3 72 d9 c1 e1 10 0b cf}  //weight: 2, accuracy: High
        $x_1_3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_4 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 75 00 61 00 70 00 70 00 2e 00 65 00 78 00 65 00 [0-4] 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "-a cryptonight -o stratum+tcp://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_OF_2147723991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.OF!bit"
        threat_id = "2147723991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/tr \"rundll32.exe url.dll,OpenURLA" ascii //weight: 1
        $x_1_2 = "shutdown -s -t 1" ascii //weight: 1
        $x_1_3 = {50 72 6f 63 65 73 73 20 48 61 63 6b 65 72 [0-3] 41 6e 56 69 72}  //weight: 1, accuracy: Low
        $x_2_4 = "LS1kb25hdGUtbGV2ZWw9MQ==" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_OF_2147723991_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.OF!bit"
        threat_id = "2147723991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /create /tn \\Systasks\\ServiceRun /tr \"C:\\ProgramData\\" ascii //weight: 1
        $x_1_2 = "taskkill /f /im attrib.exe" ascii //weight: 1
        $x_1_3 = "attrib +s +h %userprofile%\\AppData\\Roaming" ascii //weight: 1
        $x_1_4 = {54 61 73 6b 6d 67 72 2e 65 78 65 00 74 61 73 6b 6d 67 72 2e 65 78 65 00 50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CoinMiner_OF_2147723991_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.OF!bit"
        threat_id = "2147723991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "iplogger.com" ascii //weight: 2
        $x_1_2 = "xmr.pool.minergate.com" ascii //weight: 1
        $x_2_3 = {5c 57 69 6e 64 6f 77 73 54 61 73 6b 5c [0-16] 2e 65 78 65 20 2f 72 69 20 31 20 2f 73 74 20 30 30 3a 30 30 20 2f 64 75 20 39 39 39 39 3a 35 39 20 2f 73 63 20 64 61 69 6c 79 20 2f 66}  //weight: 2, accuracy: Low
        $x_1_4 = {70 00 72 00 6f 00 63 00 65 00 78 00 70 00 2e 00 65 00 78 00 65 00 00 00 74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {54 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00 41 00 6e 00 56 00 69 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_BZ_2147724270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BZ!bit"
        threat_id = "2147724270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 3a 5c 70 72 69 76 5c 77 6f 72 6b 5c 6c 6f 6c 6f 6c 6f 5c 6d 61 6c 77 6d 6d 6d [0-32] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_CF_2147724500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.CF!bit"
        threat_id = "2147724500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pool.supportxmr.com" ascii //weight: 1
        $x_1_2 = "pool.minexmr.com" ascii //weight: 1
        $x_1_3 = "Set-MpPreference -DisableRealtimeMonitoring $true" ascii //weight: 1
        $x_1_4 = "Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CoinMiner_OM_2147724558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.OM!bit"
        threat_id = "2147724558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run" wide //weight: 1
        $x_1_2 = "ATTRIB +h +S \"C:\\ProgramData" wide //weight: 1
        $x_1_3 = "taskkill /f /im" wide //weight: 1
        $x_1_4 = "stratum+tcp://xmr.pool.minergate.com:45560" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_CX_2147724559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.CX!bit"
        threat_id = "2147724559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILESETATTRIB ( @SCRIPTDIR & \"\\svchost.exe\" , \"-RSH\"" wide //weight: 1
        $x_1_2 = "RUN ( @SCRIPTDIR & \"\\up1date.exe\" , \"\" , @SW_HIDE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_CG_2147724980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.CG!bit"
        threat_id = "2147724980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "miner.Start" ascii //weight: 2
        $x_1_2 = "/Microsoft/Network/Connections/hostdl.exe" ascii //weight: 1
        $x_1_3 = "defender.Kill()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_OR_2147724990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.OR!bit"
        threat_id = "2147724990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 00 8b 40 10 89 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {b8 4d 5a 00 00 53 56 8b 75 08 57 33 ff 66 39 06 74 07 33 c0 e9 8d 00 00 00 8b 4e 3c 81 3c 31 50 45 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {81 3c 3e 50 45 00 00 0f 85 b2 00 00 00 33 db 33 c0 89 5d f4 66 3b 44 3e 06 0f 83 a0 00 00 00 33 c9 89 4d f8 8b 47 3c 05 f8 00 00 00 c7 85 ?? ?? ff ff 2e 70 6c 61 03 c1 66 c7 85 ?? ?? ff ff 74 6f 03 c7}  //weight: 1, accuracy: Low
        $x_2_4 = {8b cb 8a 84 0d ?? ?? ff ff 04 ?? 32 c1 2a c1 c0 c0 02 02 c1 34 ?? 2a c1 04 ?? 34 ?? d0 c0 02 c1 f6 d0 34 ?? 88 84 0d ?? ?? ff ff 41 81 f9 ?? 00 00 00 72 ce}  //weight: 2, accuracy: Low
        $x_2_5 = {00 00 4e 00 49 00 48 00 49 00 4c 00 4d 00 73 00 49 00 4e 00 45 00 52 00 61 00 61 00 73 00 73 00 64 00 61 00 61 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_OV_2147725056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.OV!bit"
        threat_id = "2147725056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C choice /C Y /N /D Y /T 3 & rmdir /Q /S " wide //weight: 1
        $x_1_2 = "/C choice /C Y /N /D Y /T 3 & Del " wide //weight: 1
        $x_1_3 = {4e 61 6d 65 73 70 61 63 65 0b 44 6f 77 6e 6c 6f 61 64 44 4c 4c 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_OW_2147725085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.OW!bit"
        threat_id = "2147725085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "stratum+tcp://xmr.pool.minergate.com:45560" wide //weight: 1
        $x_1_3 = "CreateObject(\"Wscript.Shell\").Run" wide //weight: 1
        $x_1_4 = "Kill" ascii //weight: 1
        $x_1_5 = "add_Shutdown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_OX_2147725088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.OX!bit"
        threat_id = "2147725088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".setRequestHeader ( \"User-Agent\" , \"Miner\" )" wide //weight: 1
        $x_1_2 = "REGWRITE ( \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_OY_2147725105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.OY!bit"
        threat_id = "2147725105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cpuminer-multi" ascii //weight: 2
        $x_1_2 = "\\win_x86.vbs" ascii //weight: 1
        $x_1_3 = "\\RUN-X11-x86.bat" ascii //weight: 1
        $x_2_4 = {50 61 74 68 3d 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 0d 0a 53 61 76 65 50 61 74 68}  //weight: 2, accuracy: High
        $x_2_5 = {54 65 6d 70 4d 6f 64 65 0d 0a 53 69 6c 65 6e 74 3d 31}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_OT_2147725135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.OT!bit"
        threat_id = "2147725135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "https://iplogger.com/" wide //weight: 1
        $x_1_2 = "XMRig/%s libuv/%s%s" ascii //weight: 1
        $x_1_3 = "stratum+tcp://xmr.pool.minergate.com:" ascii //weight: 1
        $x_1_4 = {70 00 72 00 6f 00 63 00 65 00 78 00 70 00 2e 00 65 00 78 00 65 00 [0-6] 70 00 72 00 6f 00 63 00 65 00 78 00 70 00 36 00 34 00 2e 00 65 00 78 00 65 00 [0-6] 70 00 72 00 6b 00 69 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 [0-6] 4b 00 69 00 6c 00 6c 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_PD_2147725214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PD!bit"
        threat_id = "2147725214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 00 68 04 00 00 08 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 8b 35 ?? ?? ?? 00 b8 4d 5a 00 00 66 39 05 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 31 14 6a 00 ff 74 31 10 05 ?? ?? ?? 00 50 8b 44 31 0c 03 85 ?? ?? ?? ff 50 ff b5 ?? ?? ?? ff ff 15 ?? ?? ?? 00 0f b7 87 ?? ?? ?? 00 8d 76 28 43 3b d8 72 bf}  //weight: 1, accuracy: Low
        $x_1_3 = "schtasks /create /tn" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\System32\\attrib.exe" ascii //weight: 1
        $x_1_5 = {54 61 73 6b 6d 67 72 2e 65 78 65 00 74 61 73 6b 6d 67 72 2e 65 78 65 00 50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_PE_2147725216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PE"
        threat_id = "2147725216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2e 00 72 00 75 00 2f 00 [0-16] 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "schtasks /create /tn \\Windows\\ServiceRun /tr" ascii //weight: 1
        $x_1_3 = "cryptonight" ascii //weight: 1
        $x_1_4 = "stratum+tcp://" ascii //weight: 1
        $x_1_5 = {61 74 74 72 69 62 20 2b 73 20 2b 68 20 22 43 3a 5c [0-64] 2e 65 78 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_PF_2147725220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PF!bit"
        threat_id = "2147725220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exe -o pool.minexmr.com" ascii //weight: 1
        $x_1_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 28 29 b5 f7 d3 c3 ca a7 b0 dc 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_PG_2147725225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PG!bit"
        threat_id = "2147725225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 43 00 52 00 45 00 41 00 54 00 45 00 53 00 48 00 4f 00 52 00 54 00 43 00 55 00 54 00 20 00 28 00 20 00 22 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 40 00 53 00 54 00 41 00 52 00 54 00 55 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 22 00 [0-32] 22 00 20 00 26 00 20 00 22 00 2e 00 6c 00 6e 00 6b 00 22 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 00 55 00 4e 00 20 00 28 00 20 00 40 00 43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 20 00 26 00 20 00 22 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 20 00 26 00 20 00 22 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DP_2147725372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DP!bit"
        threat_id = "2147725372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "utkiubludki.bit" ascii //weight: 1
        $x_1_2 = {69 20 2d 4f 20 [0-128] 3a 78 20 2d 6b 20 2d 2d 6d 61 78 2d 63 70 75 2d 75 73 61 67 65 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_PK_2147725453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PK!bit"
        threat_id = "2147725453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6c 61 69 79 61 77 61 6b 75 61 6e 67 61 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 5c 77 6b 73 7a 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_3 = "stratum+tcp://get.bi-chi.com:3333 -u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_PK_2147725453_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PK!bit"
        threat_id = "2147725453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 47 3c 05 f8 00 00 00 c7 85 ?? ?? ff ff 2e 70 6c 61 03 c1 66 c7 85 ?? ?? ff ff 74 6f 03 c7}  //weight: 10, accuracy: Low
        $x_10_2 = {80 c9 ff 02 c2 32 c2 d0 c0 2a c8 b0 ?? 80 f1 ?? 2a c1 88 44 15 ?? 42 83 fa ?? 72 e0 04 00 8a 44 15}  //weight: 10, accuracy: Low
        $x_1_3 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 00 8b 40 10 89 45 fc}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 78 00 36 00 34 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 73 00 61 00 64 00 6b 00 6c 00 6a 00 6d 00 38 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "/SC MINUTE /MO 1 /F /Create /TN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_DS_2147725589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DS!bit"
        threat_id = "2147725589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xmr.pool.minergate.com" wide //weight: 1
        $x_1_2 = "$SEXEMODULE = @WINDOWSDIR & \"\\winhlp32.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_PU_2147725644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PU!bit"
        threat_id = "2147725644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stratum+tcp://workpc.biz" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_PP_2147725645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PP!bit"
        threat_id = "2147725645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "advstat777.com:3333" ascii //weight: 1
        $x_1_2 = "\\WindowsTask&powershell -NoProfile -Command (New-Object System.Net.WebClient).DownloadFile(" ascii //weight: 1
        $x_1_3 = "schtasks /create /tn " ascii //weight: 1
        $x_1_4 = {5c 57 69 6e 64 6f 77 73 54 61 73 6b 5c 75 70 64 [0-8] 20 2d 72 65 63 75 72 73 65}  //weight: 1, accuracy: Low
        $x_1_5 = {69 70 6c 6f 67 67 65 72 2e 63 6f 6d 00 00 00 00 68 74 74 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CoinMiner_PW_2147725673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PW!bit"
        threat_id = "2147725673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".down0116.info" ascii //weight: 1
        $x_1_2 = "[%d] %s kill proc: %s,file: %s" ascii //weight: 1
        $x_1_3 = "del /F /ARHS \"%s\"" ascii //weight: 1
        $x_1_4 = "/C ping 127.0.0.1 -n 6 & taskkill -f /im conime.exe /im" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CoinMiner_PW_2147725673_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PW!bit"
        threat_id = "2147725673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-o stratum+tcp://%s -u %s" ascii //weight: 1
        $x_1_2 = "://%s:8888/md5.txt" ascii //weight: 1
        $x_1_3 = "://%s:8888/xmrok.txt" ascii //weight: 1
        $x_1_4 = "pubyun.com/dyndns/getip" ascii //weight: 1
        $x_1_5 = "access sina blog ok, host: %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CoinMiner_PQ_2147725791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PQ!bit"
        threat_id = "2147725791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6e 65 77 6e 65 77 6e 65 77 6e 65 77 6e 65 77 6e 65 77 6e 65 77 77 74 66 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 61 73 68 72 61 74 65 00 69 64 00 77 6f 72 6b 65 72 5f 69 64 00 62 72 61 6e 64 00 61 65 73 00 78 36 34 00 73 6f 63 6b 65 74 73 00 76 65 72 73 69 6f 6e 00 31 37 2e 33 2e 37 31 33 31 2e 31 31 35 00 6b 69 6e 64 00 63 70 75 00}  //weight: 1, accuracy: High
        $x_1_3 = {31 37 2e 33 2e 37 31 33 31 2e 31 31 35 00 4d 69 63 72 6f 73 6f 66 74 20 4f 6e 65 44 72 69 76 65 00 25 73 2f 25 73 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 25 6c 75 2e 25 6c 75 00 29 20 6c 69 62 75 76 2f 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_CA_2147726025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.CA!bit"
        threat_id = "2147726025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8c 24 3c 04 00 00 89 34 24 81 f1 [0-4] 89 c8 89 8c 24 3c 04 00 00 f7 e2 c1 ea 08 69 d2 33 01 00 00 29 d1 8b 04 8d 80 26 48 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_3 = "cpuminer-multi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QD_2147726126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QD!bit"
        threat_id = "2147726126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/click.php?cnv_id=" wide //weight: 2
        $x_2_2 = "-o stratum+tcp://xmr-eu1.nanopool.org:" wide //weight: 2
        $x_1_3 = "-p x --donate-level=1 -B --max-cpu-usage=90 -t" wide //weight: 1
        $x_1_4 = "\\xbooster\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_QB_2147726234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QB!bit"
        threat_id = "2147726234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUN ( \"system.exe -o stratum+tcp://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QE_2147726236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QE!bit"
        threat_id = "2147726236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 72 79 62 61 69 6b 6f 6c 62 61 73 61 2e 62 69 74 00}  //weight: 10, accuracy: High
        $x_1_2 = "CheckMiner" ascii //weight: 1
        $x_1_3 = "BadProcess" ascii //weight: 1
        $x_1_4 = "ProcessHacker.exe" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "--cpu-priority=0 --donate-level=1 -o {POOL_ADDRESS}:{POOL_PORT}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_QG_2147726256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QG!bit"
        threat_id = "2147726256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 3a 5c 5f 77 6f 72 6b 5c 6d 69 6e 65 72 5c 70 6c 61 79 65 72 69 6e 73 74 61 6c 6c 5c 52 65 6c 65 61 73 65 5c [0-32] 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_10_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 75 00 70 00 2e 00 68 00 6f 00 73 00 74 00 2f 00 [0-32] 2e 00 7a 00 69 00 70 00}  //weight: 10, accuracy: Low
        $x_1_3 = {5c 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 6a 00 73 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 53 00 59 00 53 00 5f 00 43 00 48 00 45 00 43 00 4b 00 5f 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 53 00 59 00 53 00 5f 00 54 00 41 00 53 00 4b 00 5f 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 53 00 59 00 53 00 5f 00 49 00 4e 00 53 00 54 00 5f 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_QH_2147726299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QH!bit"
        threat_id = "2147726299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-o pool.supportxmr.com:5555 -u" ascii //weight: 1
        $x_1_2 = {00 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_CS_2147726356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.CS!bit"
        threat_id = "2147726356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 48 00 65 00 61 00 6c 00 74 00 68 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "stratum+tcp://logoprotiger.xyz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_CY_2147726391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.CY"
        threat_id = "2147726391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b9 00 97 49 01 ff 15 ?? ?? ?? ?? c7 45 ?? ?? 00 00 00 48 8b 55 ?? 48 83 c2 e8 83 c8 ff f0 0f c1 42 10 83 e8 01 0f 8f ?? ?? ?? ?? 48 8b 0a 48 8b 01 ff 50 08 8b 7c 24 ?? e9 ?? ?? ff ff 48 8d 95 ?? ?? 00 00 48 8d 8d ?? ?? 00 00 ff 15 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d 8d ?? ?? 00 00 ff 15 ?? ?? ?? ?? 48 8d 3d ?? ?? ?? ?? 48 89 7d ?? 44 8b 2d ?? ?? ?? ?? 44 89 6c 24 ?? 48 2b de 48 81 fb 80 51 01 00}  //weight: 3, accuracy: Low
        $x_1_2 = "\"donate-level\": 0" ascii //weight: 1
        $x_1_3 = "\"log-file\": null" ascii //weight: 1
        $x_1_4 = "\"url\": \"pool.minexmr.to:4444\"" ascii //weight: 1
        $x_1_5 = "\"worker-id\": null" ascii //weight: 1
        $x_1_6 = "\"max-cpu-usage\": 70" ascii //weight: 1
        $x_3_7 = "\"user\": \"42oxdv2TkS4h99gatDAxUAdm5DcgwVApx5UJfKiNaeqwLs6EWdZPgJk72Z2LyNLWTefPTNQ9KkQ7n4n9ZCeX4ePbNyxWJ3r\"" ascii //weight: 3
        $x_2_8 = "\"pass\": \"x\"" ascii //weight: 2
        $x_1_9 = "&ea=cdl_i%d_e%d_d%d" ascii //weight: 1
        $x_1_10 = "&ea=cw_%d_%d" ascii //weight: 1
        $x_1_11 = "&ea=edl_i%d_e%d_d%d" ascii //weight: 1
        $x_1_12 = "&ea=er_i%d_e%d_r%d" ascii //weight: 1
        $x_1_13 = "&ea=ew_%d_%d" ascii //weight: 1
        $x_2_14 = "v=1&tid=%s&cid=%s&t=event&ec=exec" ascii //weight: 2
        $x_2_15 = "://%s.%s/%d/%d/?o=%d&v=%s&ts=%llu&tl=%llu&i=%lu&ec=%d&uc=%d" ascii //weight: 2
        $x_1_16 = "{f1d447af-1ba2-4af0-9584-8183fc87d66a}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_CQ_2147726436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.CQ!bit"
        threat_id = "2147726436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WindowsUpdater.exe -l luckpool.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QJ_2147726500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QJ"
        threat_id = "2147726500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "try \"\" --help' for more information." ascii //weight: 2
        $x_2_2 = "usage:  [options]" ascii //weight: 2
        $x_1_3 = "fee.xmrig.com" ascii //weight: 1
        $x_1_4 = "-o, --url=URL" ascii //weight: 1
        $x_1_5 = "cryptonight (default) or cryptonight-lite" ascii //weight: 1
        $x_1_6 = "-a, --algo=algo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_CZ_2147726774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.CZ"
        threat_id = "2147726774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 2e 8a 19 13 c7 44 24 48 98 fa 2e 08}  //weight: 1, accuracy: High
        $x_1_2 = {3a 2f 2f 00 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 00 00 2e 6e 69 63 65 68 61 73 68 2e 63 6f 6d 00 00 00 2e 6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_3 = {58 4d 52 69 67 00 00 00 25 73 2f 25 73 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 25 6c 75 2e 25 6c 75 00 00 00 29}  //weight: 1, accuracy: High
        $x_1_4 = "method\":\"submit\",\"params\":{\"id\":\"%s\",\"job_id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DA_2147726799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DA"
        threat_id = "2147726799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 88 6a 3f 24 [0-16] 35 d3 08 a3 85 [0-16] 35 2e 8a 19 13}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 6e 69 63 65 68 61 73 68 2e 63 6f 6d 00 00 00 3a 2f 2f 00 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_3 = "\"method\":\"ping\",\"params\":{\"id\":\"%s\",\"client\"" ascii //weight: 1
        $x_1_4 = {58 4d 52 69 67 00 00 00 25 73 2f 25 73 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 25 6c 75 2e 25 6c 75 00 00 00 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DA_2147726799_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DA"
        threat_id = "2147726799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s /n /s /i:\"/%016I64x /q\" \"%s\"" wide //weight: 1
        $x_1_2 = {2f 71 00 00 2f 69 6e 00 2f 63 70 00 2f 76 61 00 2f 76 78 78 76}  //weight: 1, accuracy: High
        $x_1_3 = {73 65 72 76 65 72 5f 70 61 74 68 00 2f 70 2f}  //weight: 1, accuracy: High
        $x_1_4 = "activity_domains" ascii //weight: 1
        $x_1_5 = "miner_activity" ascii //weight: 1
        $x_1_6 = "idle_poll_interval" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DA_2147726799_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DA"
        threat_id = "2147726799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c8 8a d0 0f b6 d8 80 e2 3f 0f af d9 32 98 ?? ?? ?? ?? 80 c3 77 0f b6 cb 88 98 ?? ?? ?? ?? 40 88 91 ?? ?? ?? ?? 83 f8 41 72 d4}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 6e 69 63 65 68 61 73 68 2e 63 6f 6d 00 00 00 3a 2f 2f 00 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_3 = "\"method\":\"ping\",\"params\":{\"id\":\"%s\",\"client\"" ascii //weight: 1
        $x_1_4 = {58 4d 52 69 67 00 00 00 25 73 2f 25 73 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 25 6c 75 2e 25 6c 75 00 00 00 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QM_2147727043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QM!bit"
        threat_id = "2147727043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CurrentVersion\\Policies\\Explorer\\Run\\ADSL Dial" ascii //weight: 1
        $x_1_2 = "CPU.exe -a cryptonight -o stratum+tcp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QM_2147727043_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QM!bit"
        threat_id = "2147727043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cryptonight -o stratum+tcp://xmr.pool.minergate.com" wide //weight: 1
        $x_1_2 = "http://bytecoin.tk/m/system32.exe" wide //weight: 1
        $x_1_3 = "HTTPPOST ( \"http://bytecoin.tk/m/minestatus/mns.php\"" wide //weight: 1
        $x_1_4 = "HTTPGET ( \"http://bytecoin.tk/m/minemail.txt\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CoinMiner_QN_2147727385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QN!bit"
        threat_id = "2147727385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set WshShell = WScript.CreateObject(\"WScript.Shell\")" wide //weight: 1
        $x_1_2 = "\"taskmgr.exe\"" wide //weight: 1
        $x_1_3 = "cryptonight -o stratum+tcp://pool.minexmr.com:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QN_2147727385_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QN!bit"
        threat_id = "2147727385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-o stratum+tcp://s.antminepool.com:6234" ascii //weight: 10
        $x_10_2 = "-o stratum+tcp://wk5.cybtc.info:6688 -u" ascii //weight: 10
        $x_5_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
        $x_5_4 = "type= own type= interact start= auto" ascii //weight: 5
        $x_5_5 = "cmd /c icacls c:\\ /setintegritylevel M" ascii //weight: 5
        $x_1_6 = "del /f /a /q \"c:\\windows\\system32\\drivers" ascii //weight: 1
        $x_1_7 = "copy c:\\windows\\system32\\drivers" ascii //weight: 1
        $x_1_8 = "attrib -s -h -r" ascii //weight: 1
        $x_1_9 = "SELECT * FROM Win32_process where name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_QP_2147727411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QP!bit"
        threat_id = "2147727411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "steamnezox@mail.ru" wide //weight: 1
        $x_1_2 = "SHELLEXECUTE ( \"schtasks.exe\" , \"/create /tn \"\"\\Windows\\Recovery" wide //weight: 1
        $x_1_3 = "FILESETATTRIB ( @SCRIPTDIR & \"\\config.json\" , \"+S+H" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QO_2147727414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QO!bit"
        threat_id = "2147727414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "115,116,114,97,116,117,109,43,116,99,112,58" ascii //weight: 1
        $x_1_2 = "\\Fonts\\1sass.exe" ascii //weight: 1
        $x_1_3 = "\\MSBuild\\Services.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QO_2147727414_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QO!bit"
        threat_id = "2147727414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stratum+tcp://xmr.pool.minergate.com:" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" ascii //weight: 1
        $x_1_3 = "Usage: xmrig [OPTIONS]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QO_2147727414_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QO!bit"
        threat_id = "2147727414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://pmxmrnull.dynu.net:" ascii //weight: 5
        $x_2_2 = "Pandemic-Controller-XMRIg" ascii //weight: 2
        $x_1_3 = "/tasks/getTask" ascii //weight: 1
        $x_1_4 = "REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v" ascii //weight: 1
        $x_1_5 = "schtasks /create /sc minute  /mo 1 /tn" ascii //weight: 1
        $x_1_6 = "taskkill /f /im" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_QK_2147727891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QK!bit"
        threat_id = "2147727891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "explores.exe -a cryptonight -o stratum+tcp:" ascii //weight: 1
        $x_1_2 = {a3 d6 b9 cd da bf f3}  //weight: 1, accuracy: High
        $x_1_3 = "AutoRunApp.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QX_2147728058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QX!bit"
        threat_id = "2147728058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUN ( @COMSPEC & \" /c \" & \"attrib +s +h C:\\\" & $1 , \"\" , @SW_HIDE )" wide //weight: 1
        $x_1_2 = "FILECOPY ( $PATHSCRIPT , \"C:\\\" & $2 & \"\\css.scr\" , 9 )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QX_2147728058_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QX!bit"
        threat_id = "2147728058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 55 00 4e 00 20 00 28 00 20 00 22 00 [0-32] 2e 00 65 00 78 00 65 00 20 00 2d 00 6f 00 20 00 73 00 74 00 72 00 61 00 74 00 75 00 6d 00 2b 00 74 00 63 00 70 00 3a 00 2f 00 2f 00 78 00 6d 00 72 00 2e 00 70 00 6f 00 6f 00 6c 00 2e 00 6d 00 69 00 6e 00 65 00 72 00 67 00 61 00 74 00 65 00 2e 00 63 00 6f 00 6d 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_2 = "IF PROCESSEXISTS ( \"taskmgr.exe\" ) OR PROCESSEXISTS ( \"procexp.exe\" )" wide //weight: 1
        $x_1_3 = "-p x\" , \"\" , @SW_HIDE )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QY_2147728303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QY!bit"
        threat_id = "2147728303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "windows\\system\\com4.{241d7c96-f8bf-4f85-b01f-e2b043341a4b}" ascii //weight: 1
        $x_1_2 = "svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_3 = "minergate" ascii //weight: 1
        $x_1_4 = "@gmail.com" ascii //weight: 1
        $x_1_5 = "CPU load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_RA_2147728370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.RA!bit"
        threat_id = "2147728370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 74 65 72 6e 61 6c 42 6c 75 65 5c 45 6d 70 74 79 50 72 6f 6a 65 63 74 [0-32] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "Intel Storage Service" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_RB_2147728486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.RB!bit"
        threat_id = "2147728486"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "shutdown -s -t" ascii //weight: 1
        $x_1_2 = {6f 70 65 6e 00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {8a c1 04 25 30 44 0d ?? 41 83 f9 09 72 f2}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 48 25 30 4c 04 ?? 40 83 f8 02 72 f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_RF_2147728618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.RF!bit"
        threat_id = "2147728618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\System32\\WinUpdate.exe -o pool.supportxmr.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_RG_2147728707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.RG!bit"
        threat_id = "2147728707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUN ( @APPDATADIR & \"\\System32\\DriversAVI.exe" wide //weight: 1
        $x_1_2 = "RUN ( @APPDATADIR & \"\\System32\\WinUpdate.exe" wide //weight: 1
        $x_1_3 = "--max-cpu-usage" wide //weight: 1
        $x_1_4 = "--cuda-launch" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_RH_2147728722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.RH!bit"
        threat_id = "2147728722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "g4rm0n.had.su" ascii //weight: 1
        $x_1_2 = "config.txt" ascii //weight: 1
        $x_1_3 = "nvidia.txt" ascii //weight: 1
        $x_1_4 = "bitcoincash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_2147729734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner!MTB"
        threat_id = "2147729734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c taskkill /im taskmgr.exe /f /T" ascii //weight: 1
        $x_1_2 = "cmd /c taskkill /im rundll32.exe /f /T" ascii //weight: 1
        $x_1_3 = "cmd /c taskkill /im autoruns.exe /f /T" ascii //weight: 1
        $x_1_4 = "cmd /c taskkill /im perfmon.exe /f /T" ascii //weight: 1
        $x_1_5 = "cmd /c taskkill /im procexp.exe /f /T" ascii //weight: 1
        $x_1_6 = "cmd /c taskkill /im ProcessHacker.exe /f /T" ascii //weight: 1
        $x_5_7 = "XMRig" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_DD_2147729888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DD"
        threat_id = "2147729888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"currency\" : \"m0n3r07\"," ascii //weight: 1
        $x_1_2 = "process hacker" ascii //weight: 1
        $x_1_3 = "Anvir Task Manager Free" ascii //weight: 1
        $x_1_4 = "Anvir Task Manager" ascii //weight: 1
        $x_1_5 = "Auslogics Task Manager" ascii //weight: 1
        $x_1_6 = "F:\\calculator\\Hasher\\hasher-ng\\bin\\Win32\\Release\\dssec.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_CoinMiner_CL_2147730430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.CL!bit"
        threat_id = "2147730430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 7d 0c 7e 17 56 8b 45 08 8d 34 07 8b c3 e8 ?? ?? ?? ff 30 06 47 3b 7d 0c 7c eb}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 89 88 ?? ?? ?? 00 8a 0c 01 30 0a 8b 90 ?? ?? ?? 00 8a 14 02 8b 88 ?? ?? ?? 00 30 14 01 8b 90 ?? ?? ?? 00 8a 14 02 8b 88 ?? ?? ?? 00 30 14 01 8b 88 ?? ?? ?? 00 8b 90 ?? ?? ?? 00 0f b6 0c 01 0f b6 14 02 03 ca 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8a 04 01}  //weight: 1, accuracy: Low
        $x_1_3 = {00 6d 69 6e 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DE_2147730431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DE!bit"
        threat_id = "2147730431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "delxmr.bat" ascii //weight: 2
        $x_2_2 = "svchost.exe" ascii //weight: 2
        $x_2_3 = "stratum+tcp://pool.minexmr.com:7777 -u" ascii //weight: 2
        $x_1_4 = "minergate.com" ascii //weight: 1
        $x_1_5 = "nicehash.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_DV_2147731332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DV!bit"
        threat_id = "2147731332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 b8 4d 5a 00 00 66 39 01 74 13 68 c1 00 00 00 ff 15 ?? ?? ?? 00 5e 33 c0 5b 8b e5 5d c3 8b 51 3c 8d 82 f8 00 00 00 3b d8 72 c3 81 3c 0a 50 45 00 00 8d 1c 0a 75 d4 b8 4c 01 00 00 66 39 43 04}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 05 ff b6 84 00 00 00 8b 78 0c 57 89 7d e0 ff 15 ?? ?? ?? 00 50 57 ff 15 ?? ?? ?? 00 8b f8 89 45 e4 85 ff 74 0c 57 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 73 30 8b 46 fc 6a 04 68 00 10 00 00 03 c2 51 50 8b 43 1c ff d0 83 c4 14 85 c0 74 4a ff 36 8b 46 04 8b 7e fc 03 45 08 03 7d 14 50 57 e8 ?? ?? ?? 00 89 7e f8 8b 55 14 83 c4 0c 8b 03 83 c6 28 8b 7d fc 47 89 7d fc 0f b7 40 06 3b f8 0f 8c 5e ff ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {89 77 04 0f b7 43 16 c1 e8 0d 83 e0 01 89 47 14 8b 45 10 89 47 1c 8b 45 14 89 47 20 8b 45 18 89 47 24 8b 45 1c 89 47 28 8b 45 20 89 47 2c 8b 45 24 89 47 30 8b 45 dc 89 47 38 ff 73 54 ff 75 0c e8}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 08 85 c0 74 16 83 78 14 00 75 10 8b 48 34 85 c9 74 09 83 78 18 00 74 03 5d ff e1 83 c8 ff 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_AE_2147731355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.AE"
        threat_id = "2147731355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stratum+tcp://pool.supportxmr.com" ascii //weight: 1
        $x_1_2 = "\\taskmgr.exe.lnk" ascii //weight: 1
        $x_1_3 = "svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DG_2147731739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DG!bit"
        threat_id = "2147731739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 6f 77 77 77 63 2e 63 6f 6d 2f 6d 6d 2f [0-48] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "MzkuMTA5LjE" ascii //weight: 1
        $x_1_3 = "mine.c3pool.com" ascii //weight: 1
        $x_1_4 = "xmr.f2pool.com" ascii //weight: 1
        $x_1_5 = "XMRig.exe|XMR.exe|" ascii //weight: 1
        $x_1_6 = "dS5vd3d3Yy5jb218O" ascii //weight: 1
        $x_1_7 = "49hnmvTh3gHFZVQjMXpFWfKuvF1SgDGWCQRMhStgEg6vhtJfQ8RdSAf3TYr3FoZCYyDyNainwwzRmPanT1ucBx1y5vaRXBM.r9n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CoinMiner_AF_2147733393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.AF"
        threat_id = "2147733393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hapi-ms-win-core-synch-l1-2-0.dll" wide //weight: 1
        $x_1_2 = "/github.com/Bendr0id/CmrcServiceCC/wiki/Coin-configurations" ascii //weight: 1
        $x_1_3 = "submit\",\"params\":{\"id\":\"%s\",\"job_id\":\"%s\",\"nonce\":\"%s\",\"result" ascii //weight: 1
        $x_1_4 = "Trend Micro Titanium" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DH_2147733530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DH!bit"
        threat_id = "2147733530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D7DSVcLE1jFz5ueg5Y45k3Bm6hr65v3tep" ascii //weight: 1
        $x_1_2 = "-a yescrypt -o" ascii //weight: 1
        $x_1_3 = "stratum+tcp://yescrypt.na.mine.zpool.ca:6233" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DH_2147733530_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DH!bit"
        threat_id = "2147733530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "stratum + tcp:" wide //weight: 1
        $x_1_2 = {88 04 30 8b 8e ?? ?? ?? ?? 8b c1 99 f7 fb 8a 04 3a 88 84 0e 0d 00 8b 86 ?? ?? ?? ?? 48 89 86}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 04 31 30 02 8b 86 ?? ?? ?? ?? 8b 8e ?? ?? ?? ?? 0f b6 04 30 30 04 31 8b 86 ?? ?? ?? ?? 8b 8e ?? ?? ?? ?? 0f b6 04 30 30 04 31}  //weight: 1, accuracy: Low
        $x_1_4 = {40 70 69 6e 67 20 2d 6e [0-16] 31 32 37 2e 30 2e 30 2e 31 26 64 65 6c}  //weight: 1, accuracy: Low
        $x_1_5 = "BypassUac" wide //weight: 1
        $x_1_6 = "CopyMoneroToDstPath faild, %s delete faild by:%d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DL_2147733574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DL!bit"
        threat_id = "2147733574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c [0-16] 2d 2d 6d 61 78 2d 63 70 75 2d 75 73 61 67 65 [0-16] 2d 6f [0-80] 2d 75 [0-80] 2d 70 [0-80] 2d 6b}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c [0-80] 2d 2d 63 75 64 61 2d 6d 61 78 2d 74 68 72 65 61 64 73 3d [0-80] 2d 2d 63 75 64 61 2d 62 66 61 63 74 6f 72 3d [0-80] 2d 2d 63 75 64 61 2d 62 73 6c 65 65 70 3d [0-80] 2d 6f [0-80] 2d 75 [0-80] 2d 70 [0-80] 2d 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c [0-80] 2d 6f [0-80] 2d 75 [0-80] 2d 70 [0-80] 2d 6b}  //weight: 1, accuracy: Low
        $x_2_4 = "dS5vd3d3YS5jb218OTUzMQ==" ascii //weight: 2
        $x_2_5 = "MTAzLjIxOC4yLjE0NHw5NTMx" ascii //weight: 2
        $x_3_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 3
        $x_3_7 = {63 73 63 72 69 70 74 20 2f 2f 62 20 2f 2f 6e 6f 6c 6f 67 6f 20 25 74 6d 70 25 2f [0-32] 2e 76 62 73}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_DM_2147734137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DM!bit"
        threat_id = "2147734137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c del" ascii //weight: 1
        $x_1_2 = "cryptonight" ascii //weight: 1
        $x_1_3 = "stratum+tcp://pool.minexmr.com:80 -u" ascii //weight: 1
        $x_1_4 = "blackmoon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QS_2147734620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QS!bit"
        threat_id = "2147734620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "taskkill /im dllhot.exe /f" ascii //weight: 1
        $x_1_2 = "dllhot.exe --auto --any --forever --keepalive" ascii //weight: 1
        $x_1_3 = {2d 2d 76 61 72 69 61 74 69 6f 6e 20 32 30 20 2d 2d 6c 6f 77 20 2d 6f 20 [0-32] 20 2d 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QT_2147734626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QT!bit"
        threat_id = "2147734626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.foxovsky.ru" ascii //weight: 1
        $x_1_2 = "[CPUMinerThread] - SUCCESS injected to pId:" ascii //weight: 1
        $x_1_3 = "[WinMain] - Bot installed, start SupremeThread" ascii //weight: 1
        $x_1_4 = "/gate/connection.php" ascii //weight: 1
        $x_1_5 = {69 6e 73 74 61 6c 6c 00 64 64 6f 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CoinMiner_SA_2147734919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.SA"
        threat_id = "2147734919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PowerShell.exe" wide //weight: 1
        $x_1_2 = "-ExecutionPolicy Bypass -c & 'C:\\Windows\\System32\\drivers\\cspsvc.ps1' -SCMStart" wide //weight: 1
        $x_1_3 = "cspsvc.exe" wide //weight: 1
        $x_1_4 = "System32\\drivers\\cspsvc.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_SC_2147735461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.SC!bit"
        threat_id = "2147735461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 1b 8b 4d ?? 03 4d ?? 0f be 11 8b 45 ?? 83 c0 55 33 d0 8b 4d ?? 03 4d ?? 88 11}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 89 4d ?? 0f be 45 08 8b 4d 0c 83 c1 55 33 c1 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_3 = {64 a1 18 00 00 00 8b 40 30 80 78 02 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DZ_2147735468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DZ!bit"
        threat_id = "2147735468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kingdombooter.cf/Miner.html" wide //weight: 1
        $x_1_2 = "\\Google\\Chrome\\Application\\chrome.exe --headless --remote-debugging-port=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DY_2147735469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DY!bit"
        threat_id = "2147735469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://gey.moy.su/ammyy.zip" ascii //weight: 2
        $x_2_2 = "http://gey.moy.su/temp.zip" ascii //weight: 2
        $x_1_3 = "\\system\\svchost.exe" ascii //weight: 1
        $x_1_4 = "updata.reboot@gmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_RD_2147735972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.RD!bit"
        threat_id = "2147735972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AutoRunApp.vbs" ascii //weight: 1
        $x_1_2 = "/nologo %tmp%/delay.vbs" ascii //weight: 1
        $x_1_3 = {2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c [0-16] 2d 2d 6d 61 78 2d 63 70 75 2d 75 73 61 67 65 [0-16] 2d 6f [0-80] 2d 75 [0-80] 2d 70 [0-80] 2d 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_DA_2147740133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DA!MTB"
        threat_id = "2147740133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "serba12she" ascii //weight: 1
        $x_1_2 = "taskkill /im wscript.exe /f" ascii //weight: 1
        $x_1_3 = "\\tao.vbs" ascii //weight: 1
        $x_1_4 = "\\ls.vbs" ascii //weight: 1
        $x_1_5 = "Wscript.CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_6 = "WshShell.Run" ascii //weight: 1
        $x_1_7 = "chromea.exe" ascii //weight: 1
        $x_1_8 = "chromes.exe" ascii //weight: 1
        $x_1_9 = "cryptonight" ascii //weight: 1
        $x_1_10 = "--donate-level" ascii //weight: 1
        $x_1_11 = "stratum+tcp" ascii //weight: 1
        $x_1_12 = "\\CurrentVersion\\Policies\\Explorer\\Run\\ADSL Dial" ascii //weight: 1
        $x_1_13 = "C:\\start.cmd" ascii //weight: 1
        $x_1_14 = "@taskmgr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (13 of ($x*))
}

rule Trojan_Win32_CoinMiner_GG_2147745134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.GG!MTB"
        threat_id = "2147745134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MINER {0}   CPU {1}%   RAM {2}%" ascii //weight: 10
        $x_10_2 = "Select * from AntivirusProduct" ascii //weight: 10
        $x_10_3 = "/create /f /sc ONLOGON /RL HIGHEST /tn" ascii //weight: 10
        $x_1_4 = "Pastebin" ascii //weight: 1
        $x_1_5 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 1
        $x_1_6 = "schtasks.exe" ascii //weight: 1
        $x_1_7 = "--donate-level=" ascii //weight: 1
        $x_1_8 = "SELECT CommandLine FROM Win32_Process WHERE ProcessId = " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_BM_2147745439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.BM!MSR"
        threat_id = "2147745439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "log.boreye.com" ascii //weight: 2
        $x_1_2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkPlatform\\Location" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_RS_2147756269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.RS!MTB"
        threat_id = "2147756269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xmrig.exe" wide //weight: 1
        $x_1_2 = "DisableAntiSpyware" wide //weight: 1
        $x_1_3 = "DisableBehaviorMonitoring" wide //weight: 1
        $x_1_4 = "DisableOnAccessProtection" wide //weight: 1
        $x_1_5 = "DisableScanOnRealtimeEnable" wide //weight: 1
        $x_1_6 = "stratum" wide //weight: 1
        $x_1_7 = "verysilent" wide //weight: 1
        $x_1_8 = "Khsopeyrkdmva" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_CoinMiner_RM_2147787411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.RM!MTB"
        threat_id = "2147787411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "E:\\CryptoNight\\bitmonero-master\\src\\miner\\Release\\Crypto.pdb" ascii //weight: 10
        $x_10_2 = "byk\\:2L" ascii //weight: 10
        $x_1_3 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_4 = "LoadLibraryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_QS_2147807545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.QS!MTB"
        threat_id = "2147807545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\POWR" ascii //weight: 3
        $x_3_2 = "newMinerProxy/proxy" ascii //weight: 3
        $x_3_3 = "fGxakzVydtejWSsONP5b8A==" ascii //weight: 3
        $x_3_4 = "END PRIVATE KEY" ascii //weight: 3
        $x_3_5 = "proxy.process" ascii //weight: 3
        $x_3_6 = "SetProcessPriorityBoost" ascii //weight: 3
        $x_3_7 = "CreateWaitableTimerExW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_XO_2147808512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.XO"
        threat_id = "2147808512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://mail.techniservinc.com/resources/files/" wide //weight: 2
        $x_1_2 = "O_T.exe" wide //weight: 1
        $x_1_3 = "LC_KEY_L" wide //weight: 1
        $x_1_4 = "LC_DLL_L" wide //weight: 1
        $x_1_5 = "LC_DATA1_L" wide //weight: 1
        $x_1_6 = "LC_DATA2_L" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_GD_2147811466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.GD!MTB"
        threat_id = "2147811466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PhoenixMiner" ascii //weight: 1
        $x_1_2 = "Kryptex" ascii //weight: 1
        $x_1_3 = "nanominer" ascii //weight: 1
        $x_1_4 = "prometherion" ascii //weight: 1
        $x_1_5 = "powershell" ascii //weight: 1
        $x_1_6 = "EthDcrMiner64" ascii //weight: 1
        $x_1_7 = "t-rex" ascii //weight: 1
        $x_1_8 = "xmrig-cuda.dll" ascii //weight: 1
        $x_1_9 = "config.txt" ascii //weight: 1
        $x_1_10 = "stc.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_CoinMiner_AL_2147815005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.AL!MTB"
        threat_id = "2147815005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 03 83 f3 ?? fe cb 33 d9 64 a1 [0-4] 1b de 8b d0 02 f9 73 05}  //weight: 2, accuracy: Low
        $x_2_2 = {31 3a 8b df 2b d9 8b 32 21 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_CB_2147817137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.CB!MTB"
        threat_id = "2147817137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 03 01 cf 81 ef [0-4] 81 c3 04 00 00 00 be [0-4] 81 e9 [0-4] 39 d3 75 dc}  //weight: 2, accuracy: Low
        $x_2_2 = {89 db 31 10 4b 41 01 db 40 01 cb 39 f8 75 d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CoinMiner_DF_2147821124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.DF!MTB"
        threat_id = "2147821124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d0 8b 4d f0 c1 e9 05 03 4d d8 33 d1 8b 45 d4 2b c2 89 45 d4 8b 4d e8 2b 4d dc 89 4d e8 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_RDE_2147841307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.RDE!MTB"
        threat_id = "2147841307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "666_RaumWithMe_666" ascii //weight: 1
        $x_1_2 = "WinDDK" ascii //weight: 1
        $x_1_3 = "tools/regwrite.raum_encrypted" ascii //weight: 1
        $x_1_4 = "Mozilla/5.0 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)" ascii //weight: 1
        $x_1_5 = "SELECT * FROM" ascii //weight: 1
        $x_1_6 = "AntiVirusProduct" ascii //weight: 1
        $x_1_7 = "Win32_VideoController" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_RPQ_2147845191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.RPQ!MTB"
        threat_id = "2147845191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Taskmgr.exe" ascii //weight: 1
        $x_1_2 = "Stopper-mutex" ascii //weight: 1
        $x_1_3 = "method/wall.get.xml" ascii //weight: 1
        $x_1_4 = "Raum-with-Me" ascii //weight: 1
        $x_1_5 = "mining_info" ascii //weight: 1
        $x_1_6 = "tools/regwrite.raum_encrypted" ascii //weight: 1
        $x_1_7 = "<encryption_key>" ascii //weight: 1
        $x_1_8 = "No evil here, trust me" ascii //weight: 1
        $x_1_9 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_10 = "GetForegroundWindow" ascii //weight: 1
        $x_1_11 = "Kaspersky" ascii //weight: 1
        $x_1_12 = "avast" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_ABS_2147850827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.ABS!MTB"
        threat_id = "2147850827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 14 e5 b7 a9 d3 d4 8a 06 66 0f ca 48 8d 96 48 b6 8c c4 48 ff c6 39 c2 66 0f be d2 28 d8 88 d2 f9 0f ba f2 0b d2 de c0 c0 04 66 0f ca 66 0f b6 d1 89 d2 fe c8 e9 a7 0f 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "dkjihgfdetsrqpondm" ascii //weight: 1
        $x_1_3 = "E:\\CryptoNight\\bitmonero-master\\src\\miner\\x64\\CPU-Release\\Crypto.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_ABAS_2147851295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.ABAS!MTB"
        threat_id = "2147851295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\AppCache\\x86\\svchost.exe" ascii //weight: 1
        $x_1_2 = "-a m7 -o stratum+tcp://xcnpool.1gh.com:7333 -u CJJkVzjx8GNtX4z395bDY4GFWL6Ehdf8kJ.SERVER%RANDOM% -p x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_RPY_2147852905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.RPY!MTB"
        threat_id = "2147852905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 53 57 e8 95 b1 04 00 68 2a 03 00 00 e8 8b c2 20 00 8b 0d d0 26 66 00 83 c4 04 03 c8 89 0d d0 26 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_MAI_2147900138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.MAI!MTB"
        threat_id = "2147900138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loadstring(game:HttpGet(\"https://cdn.wearedevs.net/scripts/Fly.txt\"))()" ascii //weight: 1
        $x_1_2 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_3 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_ASC_2147900738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.ASC!MTB"
        threat_id = "2147900738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fkEWVwUchKSUpgmNiwiOMQNisKcFFUyQPztklKRTamtQGDgohimBB" ascii //weight: 1
        $x_1_2 = "RcSSTySieMIfIEZNcoCjFttuVthqeynzxArATUQeBuuODg" ascii //weight: 1
        $x_1_3 = "UwGngKXTdAprRcLwYqDHVfHSgUzYblHXWKyVjOP" ascii //weight: 1
        $x_1_4 = "QbFdeiiezKaBqVwUIbEXGhBpAJRmTRDLVotOqmZElahQ" ascii //weight: 1
        $x_1_5 = "FaQuMAQiyxyQgPrACtCRGvJQJStecOuHSBPjmhew" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_ASD_2147901076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.ASD!MTB"
        threat_id = "2147901076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wana Girlfirend DecryptOr 2.0" ascii //weight: 1
        $x_1_2 = "Ooops,your girlfriend hava been NTR!" ascii //weight: 1
        $x_1_3 = "How to buy a girlfriend" ascii //weight: 1
        $x_1_4 = "software\\microsoft\\windows\\CurrentVersion\\Run\\Syste2.exe" ascii //weight: 1
        $x_1_5 = "Girlfriend.txt" ascii //weight: 1
        $x_1_6 = {62 05 b5 22 d0 46 4b 2f 6f 20 4f 03 28 b5 ac de 63 20 0f 20 0f ac de 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_NC_2147901180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.NC!MTB"
        threat_id = "2147901180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 85 f6 75 08 6a ?? e8 36 b9 ff ff 59 89 35 ?? ?? ?? ?? c7 05 40 05 a6 00 ?? ?? ?? ?? 8d 86 80 04}  //weight: 5, accuracy: Low
        $x_1_2 = "del /f /s /q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_CCIB_2147912816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.CCIB!MTB"
        threat_id = "2147912816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "47.96.86.81" ascii //weight: 1
        $x_1_2 = "wmic process  get Name,ExecutablePath,ProcessId,ParentProcessId /value" ascii //weight: 1
        $x_1_3 = "C:\\Windows\\System32\\taskkill.exe /T /F /PID" ascii //weight: 1
        $x_1_4 = "c:\\windows\\process.txt" ascii //weight: 1
        $x_1_5 = "98 49 121 105 51 97 112 112 112 56 51 99 106 120 119 106 119 120 54 104 57 52 97 106 49 106 49 115 117 117 103 121 107 122 104 56 122 99 101 56 105 50 109 52 107 56 100 50 54 57 98 50 121 100 54 100 56 48 48 56 122 105 121 50" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_MC_2147914353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.MC!MTB"
        threat_id = "2147914353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d3 c1 ea 08 8b 88 cc 00 00 00 a1 98 a2 08 10 88 14 08 ff 05 98 a2 08 10 8b 15 d4 99 05 10 8b 86 90 00 00 00 8b 8a b0 00 00 00 81 c1 3b 30 f8 ff 03 c1 09 82 c0 00 00 00 8b 46 78 8b 8e cc 00 00 00 88 1c 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_GXT_2147924062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.GXT!MTB"
        threat_id = "2147924062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b f4 6a 40 68 00 30 00 00 8b 45 dc 8b 48 50 51 8b 55 dc 8b 42 34 50 8b 8d ?? ?? ?? ?? 51 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {8b f4 6a 00 8b 45 dc 8b 48 54 51 8b 55 48 52 8b 85 ?? ?? ?? ?? 50 8b 8d ?? ?? ?? ?? 51 ff 15}  //weight: 5, accuracy: Low
        $x_5_3 = {8b f4 8b 85 ?? ?? ?? ?? 50 8b 8d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 8b 85 ?? ?? ?? ?? 50 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_ACM_2147925085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.ACM!MTB"
        threat_id = "2147925085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 c1 10 6a 08 83 d0 00 50 51 8b 4c 24 20 e8 ?? ?? ?? ?? 8b 7c 24 1c 8d 94 24 f0 00 00 00 8b 44 24 18 83 c4 10 8b cf 81 c1 e0 73 08 00 89 8c 24 60 01 00 00 8b 4c 24 14 83 d0 00 89 84 24 64 01 00 00}  //weight: 3, accuracy: Low
        $x_2_2 = {8b d9 8b f2 8b d3 57 8d 7a 02 8d 64 24 00 66 8b 02 83 c2 02 66 85 c0 75 f5 8b ce 2b d7 d1 fa 8d 79 02 66 8b 01 83 c1 02 66 85 c0 75 f5 2b cf 8d 42 01 d1 f9 ba 02 00 00 00 03 c1 33 c9 f7 e2 0f 90 c1 f7 d9 0b c8 51}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_HNAB_2147930739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.HNAB!MTB"
        threat_id = "2147930739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 3e c3 6f d2 45 c3 6f 31 47 c3 6f 80 46 c3 6f 00 00 00 00 b9 8e c6 7d a9 f5 c8 7d 00 00 00 00 22 12 d7 7d 56 18 d7 7d 47 43 d7 7d 28 4d d7 7d}  //weight: 2, accuracy: High
        $x_2_2 = {3a f7 0e 66 b7 77 10 66 c1 fd 0e 66 ec 9c 0d 66 ee f6 0e 66 bf b6 0d 66 0c 94 10 66 44 77 10 66}  //weight: 2, accuracy: High
        $x_2_3 = {09 fb 0e 66 3a f8 0e 66 c9 76 10 66 53 75 10 66 1b bb 0d 66 fa 0d 0e 66}  //weight: 2, accuracy: High
        $x_1_4 = {00 ff 25 1c 11 40 00 05 00 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 74 65 78 74 00 00 00 64 08 02 00 00 10 00 00 00 10 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 64 61 74 61 00 00 00 b0 0a 00 00 00 20 02 00 00 10 00 00 00 20 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_HNAC_2147931547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.HNAC!MTB"
        threat_id = "2147931547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = ".CreateShortcut(\"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\xmrig.lnk\")" ascii //weight: 10
        $x_10_2 = "Get-ChildItem -Path '\\xmrig-*\\xmrig.exe' | Move-Item -Destination '\\svchost.exe" ascii //weight: 10
        $x_5_3 = {55 53 45 52 50 52 4f 46 49 4c 45 5c [0-192] 2e 65 78 65}  //weight: 5, accuracy: Low
        $x_5_4 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 27 27 20 2d 4f 75 74 46 69 6c 65 20 27 27 [0-96] 45 78 70 61 6e 64 2d 41 72 63 68 69 76 65 20 2d 50 61 74 68 20 27 27 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 50 61 74 68 20 27 27 20 2d 46 6f 72 63 65}  //weight: 5, accuracy: Low
        $x_5_5 = {2e 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 22 24 65 6e 76 3a 41 50 50 44 41 54 41 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c [0-192] 2e 6c 6e 6b 22 29}  //weight: 5, accuracy: Low
        $x_5_6 = {2e 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 5b 53 79 73 74 65 6d 2e 49 4f 2e 50 61 74 68 5d 3a 3a 43 6f 6d 62 69 6e 65 28 24 65 6e 76 3a 41 50 50 44 41 54 41 2c 20 27 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c [0-192] 20 [0-192] 2e 6c 6e 6b 27 29 29 3b}  //weight: 5, accuracy: Low
        $x_1_7 = {2e 53 61 76 65 28 29 [0-80] 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f}  //weight: 1, accuracy: Low
        $x_1_8 = {00 00 00 00 5c 78 6d 72 69 67 2e 65 78 65 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CoinMiner_GNT_2147932222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.GNT!MTB"
        threat_id = "2147932222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4a 1c 6f a3 ?? ?? ?? ?? 6b 37 70 11 56 ?? ec 93}  //weight: 5, accuracy: Low
        $x_5_2 = {30 53 1d 2c 7c b3 e7 4a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_PBD_2147939605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PBD!MTB"
        threat_id = "2147939605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0f b6 4d 13 8a 14 01 00 55 ff 8d 34 01 0f b6 4d ff 8a 1c 01 03 c8 88 1e 88 11 8a 1e 8b 4d f8 02 da 0f b6 d3 03 f9 8a 14 02 30 17 41 3b 4d 0c 89 4d f8}  //weight: 4, accuracy: High
        $x_2_2 = "yyrutifnvc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_TL_2147940772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.TL!MTB"
        threat_id = "2147940772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 8d cc f8 ff ff 51 6a 01 68 cd 0d 6e 52 8b 95 c4 fd ff ff 52 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_ETL_2147944192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.ETL!MTB"
        threat_id = "2147944192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c1 89 c8 d1 e8 ba 43 08 21 84 f7 e2 89 d0 c1 e8 04 6b c0 3e 29 c1 89 c8 0f b6 80 c0 92 94 62 88 03 83 45 f4 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_PAHM_2147947972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.PAHM!MTB"
        threat_id = "2147947972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 20 27 43 3a 5c [0-16] 5c 63 6f 6e 66 69 67 2e 6a 73 6f 6e 27}  //weight: 2, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_2_3 = {4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 27 00 43 00 3a 00 5c 00 [0-16] 5c 00 57 00 69 00 6e 00 52 00 69 00 6e 00 67 00 30 00 78 00 36 00 34 00 2e 00 73 00 79 00 73 00 27 00}  //weight: 2, accuracy: Low
        $x_1_4 = "powershell -Command Add-MpPreference -ExclusionPath '" wide //weight: 1
        $x_1_5 = "Downloading file from:" wide //weight: 1
        $x_1_6 = "runas" wide //weight: 1
        $x_2_7 = "xmrig" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_Z_2147951833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.Z!MTB"
        threat_id = "2147951833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3f 2c d3 51 f2 3f c2 13 1c 58 e3 61 d3 08 2d 8c 4d 70 9b 41 6f 35 1b f1 2a 16 4d 92 ae e7 d2 e3 14 33 f2 c2 d6 79 60 f0 30 38 d2 e1 f2 db 3c 74 f1 e0 38 dd cb 1c f9 ca 07 83 0f 18 e9 96 cf cd 16 1f 75 dd 01 b6 4f ca df 14 43 e2 4c 0c 8a f1 41 7e 65 88 1e 11 dd 74 c0 83 2e fc 4c 7b 99 68 bf 9a e2 24 1a b7 70 df 8b 75 80 03 3c d4 48 53 cb 22 5c 18 34 e8 83 da b3 c3 1e 22 26 b0 f2 44 23 b6 89 c1 cc 92 e7 fb ec 21 8b c6 79 e8 e3 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMiner_ZA_2147951834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMiner.ZA!MTB"
        threat_id = "2147951834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 57 21 60 88 93 9b 54 bc a2 09 49 ba 9d 91 87 e2 14 0e 9c 9d bb 69 9d 4c 20 17 21 d7 20 70 13 d6 2d 69 95 78 41 4a 85 a7 ad ab 76 0b 57 ac ed a1 f2 61 5a c2 53 02 58 6a 09 17 85 c4 b5 d7 dd a4 17 83 34 ed 45 80 b4 96 30 18 eb a6 94 53 70 84 75 b3 a1 a0 f4 14 fd 77 d7 ea 40 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


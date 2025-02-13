rule Trojan_Win32_WinSpywareProtect_122283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinSpywareProtect"
        threat_id = "122283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpywareProtect"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "42BD-A8CB-7E5" ascii //weight: 1
        $x_1_2 = "://dl.%s/get/?pin=" ascii //weight: 1
        $x_1_3 = "/scan." ascii //weight: 1
        $x_1_4 = "InternetOpenA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WinSpywareProtect_122283_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinSpywareProtect"
        threat_id = "122283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpywareProtect"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<.php?" ascii //weight: 2
        $x_2_2 = "b/html," ascii //weight: 2
        $x_1_3 = "TUNPROTECTEDCONFIRMFORM" wide //weight: 1
        $x_1_4 = "TNETATTACKDETECTIONFORM" wide //weight: 1
        $x_1_5 = "SCAN_IMG" wide //weight: 1
        $x_1_6 = "TVIRUSDESCFORM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinSpywareProtect_122283_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinSpywareProtect"
        threat_id = "122283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpywareProtect"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "func=installrun&id=%s&landing=%s&lang=%s&sub=%s&notstat=1" ascii //weight: 1
        $x_1_2 = "/pay/%s/%s/" ascii //weight: 1
        $x_1_3 = "exportdb.php?func=update&id=%s&pid=%s" ascii //weight: 1
        $x_1_4 = "AMFILES>\\sniffem\\sniffem.exe" ascii //weight: 1
        $x_1_5 = {ff ff ff ff 0c 00 00 00 4c 61 75 6e 63 68 65 72 2e 65 78 65 00 00 00 00 ff ff ff ff 0b 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_2_6 = "?type=%s&pin=%s&lnd=%s" ascii //weight: 2
        $x_2_7 = {68 74 74 70 3a 2f 2f 64 6c 2e 00 00 ff ff ff ff 05 00 00 00 2f 67 65 74 2f 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinSpywareProtect_122283_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinSpywareProtect"
        threat_id = "122283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpywareProtect"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {61 00 6e 00 74 00 69 00 73 00 70 00 79 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 2e 00 63 00 6f 00 6d 00 2b 00 73 00 74 00 61 00 74 00 2e 00 70 00 68 00 70 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 25 00 64 00 26 00 61 00 66 00 66 00 69 00 64 00 3d 00 25 00 73 00 26 00 70 00 63 00 69 00 64 00 3d 00 25 00 73 00 26 00 61 00 62 00 62 00 72 00 3d 00 25 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {25 00 73 00 5c 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 50 00 72 00 6f 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 00 73 00 5c 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 4d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 00 6e 00 74 00 69 00 53 00 70 00 79 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {4e 00 6f 00 52 00 75 00 6e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinSpywareProtect_122283_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinSpywareProtect"
        threat_id = "122283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpywareProtect"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Software\\\\LastSun Ltd.\\\\" ascii //weight: 2
        $x_2_2 = ",%s scan for malware and remove found threats" ascii //weight: 2
        $x_1_3 = "Illegal activation code! Recheck your input data!" ascii //weight: 1
        $x_1_4 = "Trojan-PSW.GOPtrojan!sd5 is a malicious application that attempts to steal passwords," ascii //weight: 1
        $x_1_5 = "IM-Flooder.ToolzY2K!sd5 is a threat that is capable to cause" ascii //weight: 1
        $x_1_6 = "This program is a new and improved approach to spyware identification and removal." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinSpywareProtect_122283_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinSpywareProtect"
        threat_id = "122283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpywareProtect"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {02 16 c1 c2 ?? 81 f2 ?? ?? ?? ?? 46 80 3e 00 75 ef 31 fa 83 fa 00 74 1b 01 c6 81 e8 ?? ?? ?? ?? 8b 30 01 ca 01 ce 5a 42 52 81 e2 ?? ?? ?? ?? 31 d2 eb cd}  //weight: 11, accuracy: Low
        $x_11_2 = {02 17 47 c1 c2 ?? 81 f2 ?? ?? ?? ?? 80 3f 00 75 ef 31 c2 83 fa 00 74 11 81 c6 04 00 00 00 8b 3e 01 cf 5a 42 52 31 d2 eb d7}  //weight: 11, accuracy: Low
        $x_11_3 = {02 17 c1 ca ?? 81 f2 ?? ?? ?? ?? 47 80 3f 00 75 ef 31 c2 83 fa 00 74 11 5a 42 52 81 c6 04 00 00 00 8b 3e 01 cf 31 d2 eb d7}  //weight: 11, accuracy: Low
        $x_9_4 = {77 69 6e 73 70 79 77 61 72 65 70 72 6f 74 65 63 74 [0-3] 2e 63 6f 6d}  //weight: 9, accuracy: Low
        $x_1_5 = "InternetReadFile" ascii //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*) and 2 of ($x_1_*))) or
            ((1 of ($x_11_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinSpywareProtect_122283_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinSpywareProtect"
        threat_id = "122283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpywareProtect"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Installation of Smart Defender PRO in progress, please wait..." ascii //weight: 2
        $x_1_2 = "%ssmrtdefp.exe" wide //weight: 1
        $x_1_3 = "abracadbra.jpg" wide //weight: 1
        $x_2_4 = "ids=%s&guid=%s&serial=%s&ntid=%s&build=%s" wide //weight: 2
        $x_3_5 = {8b c1 99 f7 ff 42 0f ?? ?? 01 00 00 3b d7 0f ?? ?? 01 00 00 0f be 04 32 89 84 8c ?? ?? 00 00 89 4c 8c ?? 41 81 f9 00 01 00 00 7c d4}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinSpywareProtect_122283_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinSpywareProtect"
        threat_id = "122283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpywareProtect"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 75 6e 63 3d 73 63 61 6e 66 69 6e 69 73 68 65 64 26 69 64 3d 25 73 00}  //weight: 5, accuracy: High
        $x_5_2 = {65 78 70 6f 72 74 64 62 2e 70 68 70 3f 66 75 6e 63 3d 75 70 64 61 74 65 26 69 64 3d 25 73 26 70 69 64 3d 25 73 00}  //weight: 5, accuracy: High
        $x_5_3 = {66 75 6e 63 3d 69 6e 73 74 61 6c 6c 26 (70|75) 69 64 3d 25 73 26 (69 70|6c 61 6e 64 69) 3d 25 73 00}  //weight: 5, accuracy: Low
        $x_5_4 = "589;Win32/Rbot.IDN;Backdoor;4;Win32/Rbot.IDN is an IRC controlled backdoor" ascii //weight: 5
        $x_2_5 = {76 62 61 73 65 2e 62 61 6b 00}  //weight: 2, accuracy: High
        $x_2_6 = {76 62 61 73 65 2e 64 61 74 00}  //weight: 2, accuracy: High
        $x_2_7 = {76 62 61 73 65 2e 74 6d 70 00}  //weight: 2, accuracy: High
        $x_2_8 = {55 70 64 61 74 65 20 64 6f 77 6e 6c 6f 61 64 20 63 6f 6d 70 6c 65 74 65 00}  //weight: 2, accuracy: High
        $x_2_9 = {45 72 72 6f 72 20 6f 63 63 75 72 73 20 77 68 69 6c 65 20 64 6f 77 6e 6c 6f 61 64 69 6e 67 20 75 70 64 61 74 65 3a 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinSpywareProtect_122283_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinSpywareProtect"
        threat_id = "122283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpywareProtect"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {68 74 74 70 3a 2f 2f [0-4] 2e 77 69 6e 73 70 79 77 61 72 65 70 72 6f 74 65 63 74 [0-2] 2e 63 6f 6d 2f [0-10] 2f 49 6e 73 74 61 6c 6c [0-6] 2e 65 78 65}  //weight: 100, accuracy: Low
        $x_100_2 = {68 74 74 70 3a 2f 2f [0-4] 2e 57 69 6e 53 70 79 77 61 72 65 50 72 6f 74 65 63 74 [0-2] 2e 63 6f 6d 2f 61 64 64 6f 6e 2f}  //weight: 100, accuracy: Low
        $x_100_3 = {68 74 74 70 3a 2f 2f [0-4] 2e 57 69 6e 53 70 79 77 61 72 65 50 72 6f 74 65 63 74 [0-2] 2e 63 6f 6d 2f 73 74 61 74 2e 70 68 70}  //weight: 100, accuracy: Low
        $x_100_4 = {68 74 74 70 3a 2f 2f [0-4] 2e 6d 61 6c 77 61 72 72 69 6f 72 [0-2] 2e 63 6f 6d 2f 61 64 64 6f 6e}  //weight: 100, accuracy: Low
        $x_100_5 = {68 74 74 70 3a 2f 2f [0-4] 2e 6d 61 6c 77 61 72 72 69 6f 72 [0-2] 2e 63 6f 6d 2f 73 74 61 74 2e 70 68 70}  //weight: 100, accuracy: Low
        $x_1_6 = "\\Adsl Software Limited\\WinSpywareProtect" ascii //weight: 1
        $x_1_7 = "\\Adsl Software Limited\\MalWarrior" ascii //weight: 1
        $x_1_8 = "Software\\Adsl Software Limited\\Installer" ascii //weight: 1
        $x_1_9 = "WinSpywareProtect installer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinSpywareProtect_122283_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinSpywareProtect"
        threat_id = "122283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpywareProtect"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Trojan.Folderfu!sd5 is a malicious program that does not infect other files but may represents security" ascii //weight: 1
        $x_1_2 = "Worm.Small!sd5 is a network-aware worm that attempts to replicate across the existing network." ascii //weight: 1
        $x_1_3 = "Windows Security Center reports that %s is not registered" ascii //weight: 1
        $x_1_4 = ",%s scan for malware and remove found threats" ascii //weight: 1
        $x_1_5 = "actDeleteVirusExecute%" ascii //weight: 1
        $x_1_6 = "acIESniffer1WBFileDownload" ascii //weight: 1
        $x_1_7 = "C:\\TEMP\\Upgrader3.exe" ascii //weight: 1
        $x_2_8 = "http://www.avpro-labs.com/buy.html" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinSpywareProtect_122283_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinSpywareProtect"
        threat_id = "122283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpywareProtect"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 00 62 00 72 00 61 00 63 00 61 00 64 00 62 00 72 00 61 00 2e 00 6a 00 70 00 67 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "i=%s&g=%s&s=%s&n=%s&b=%s&z=%i&h=%i&o=OK" wide //weight: 2
        $x_2_3 = {25 00 73 00 73 00 6d 00 72 00 74 00 64 00 65 00 66 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {6b 6c 6a 68 66 6c 6b 37 33 23 4f 4f 23 2a 55 24 4f 28 2a 59 4f 00}  //weight: 2, accuracy: High
        $x_1_5 = "Installation in progress, please wait..." wide //weight: 1
        $x_1_6 = {2e 63 6f 6d 2f 64 70 2f 00}  //weight: 1, accuracy: High
        $x_1_7 = {70 00 69 00 63 00 2e 00 6a 00 70 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {69 00 6e 00 66 00 6f 00 2e 00 6a 00 70 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_2_9 = "w=%s&g=%s&x=%s&u=%s&n=%s&p=%i&s=%i&l=OK" wide //weight: 2
        $x_1_10 = {2e 6e 65 74 2f 64 70 2f 00}  //weight: 1, accuracy: High
        $x_1_11 = {2e 69 6e 2f 64 70 2f 00}  //weight: 1, accuracy: High
        $x_2_12 = {25 00 73 00 73 00 64 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_4_13 = {6a 00 68 69 03 00 00 56 e8 ?? ?? ?? ?? 83 c4 0c 81 ff 69 03 00 00 73}  //weight: 4, accuracy: Low
        $x_4_14 = {53 68 69 03 00 00 50 e8 ?? ?? ?? ?? b8 69 03 00 00 83 c4 0c 39 85 ?? ?? ?? ?? 73}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}


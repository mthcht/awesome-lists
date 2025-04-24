rule Trojan_Win32_EyeStye_2147631403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147631403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 00 8d 85 46 00 ff 63 c6 85 ?? ?? ?? ff 6f c6 85 ?? ?? ?? ff 6e c6 85 ?? ?? ?? ff 66 c6 85 ?? ?? ?? ff 69 c6 85 ?? ?? ?? ff 67 c6 85 ?? ?? ?? ff 2e c6 85 ?? ?? ?? ff 62 c6 85 ?? ?? ?? ff 69 c6 85 ?? ?? ?? ff 6e c6 85}  //weight: 3, accuracy: Low
        $x_1_2 = {55 8b ec 51 51 8b 45 08 66 81 38 4d 5a 74 04 33 c0 c9 c3 56 8b 70 3c 03 f0 81 3e 50 45 00 00}  //weight: 1, accuracy: High
        $x_2_3 = "__CLEANSWEEP__" ascii //weight: 2
        $x_1_4 = "cleansweep.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EyeStye_2147631403_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147631403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 5f 43 4c 45 41 4e 53 57 45 45 50 5f 5f 00}  //weight: 1, accuracy: High
        $x_2_2 = {8d 45 f4 50 68 9c 96 78 bf 6a 00 e8 [0-21] ff 75 10 ff 75 0c ff 75 08 ff d0}  //weight: 2, accuracy: Low
        $x_2_3 = {80 7e 01 41 75 2f 80 7e 02 53 75 29 80 7e 03 53 75 23}  //weight: 2, accuracy: High
        $x_2_4 = {c6 45 ec 25 c6 45 ed 73 c6 45 ee 5c c6 45 ef 25 c6 45 f0 73 88 5d ?? e8}  //weight: 2, accuracy: Low
        $x_2_5 = {c6 45 6c 25 c6 45 6d 73 c6 45 6e 5c c6 45 6f 25 c6 45 70 73 88 5d ?? e8}  //weight: 2, accuracy: Low
        $n_1_6 = {2a 44 72 6f 70 70 65 72 2a 21 6d 61 69 6e 20 3a 20 43 72 65 61 74 65 4d 75 74 65 78 2d 3e 45 52 52 4f 52 5f 41 4c 52 45 41 44 59 5f 45 58 49 53 54 53 00}  //weight: -1, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EyeStye_H_2147637450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye.H"
        threat_id = "2147637450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_TENYPS__" ascii //weight: 1
        $x_1_2 = {6c 6d 78 2e [0-8] 2d 73 65 69 6b 6f 6f 63}  //weight: 1, accuracy: Low
        $x_1_3 = "EMANTOB%" ascii //weight: 1
        $x_1_4 = {1b 6a 00 43 dc fe 04 dc fe 04 0c ff 0a 08 00 08 00 04 b0 fe 04 0c ff fd fe ?? fe 04 3c ff fd fe ?? fe 07 08 00 80 00 24 0a 00 0d 20 00 0b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_EyeStye_H_2147637450_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye.H"
        threat_id = "2147637450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 6e c6 85 ?? ?? ff ff 44 c6 85 ?? ?? ff ff 72 c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 76 c6 85 ?? ?? ff ff 78 c6 85 ?? ?? ff ff 78}  //weight: 3, accuracy: Low
        $x_3_2 = {ff 6e c6 85 9f fb ?? ?? 66 c6 85 a0 fb ?? ?? 69 c6 85 a1 fb ?? ?? 67 c6 85 a2 fb ?? ?? 2e c6 85 a3 fb ?? ?? 62 c6 85 a4 fb ?? ?? 69}  //weight: 3, accuracy: Low
        $x_2_3 = "__SPYNET__" ascii //weight: 2
        $x_1_4 = {53 70 79 45 79 65 5f 53 74 6f 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 70 79 45 79 65 5f 49 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 5c 2e 5c 70 69 70 65 5c 67 6c 6f 62 70 6c 75 67 69 6e 73 70 69 70 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {45 72 72 6f 72 3a 20 54 68 72 65 61 64 20 69 73 20 72 65 61 6c 6c 79 20 73 6c 6f 70 70 79 00}  //weight: 1, accuracy: High
        $x_1_8 = {62 6f 74 5f 67 75 69 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {25 42 4f 54 4e 41 4d 45 25 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EyeStye_L_2147643689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye.L"
        threat_id = "2147643689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 6f 63 6b 73 35 2e 64 6c 6c 00 47 65 74 50 6c 75 67 69 6e 49 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 43 ff 3b c8 73 0c 8b 45 08 80 3c 01 3b 75 03 47 8b f1 3b 7d 0c 75 ?? 83 fe ff 74 09}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 17 00 00 00 66 89 16 ff 15 ?? ?? ?? ?? 66 89 46 02 8d 45 ?? 50 8b cf c7 46 04 00 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EyeStye_N_2147645167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye.N"
        threat_id = "2147645167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f8 d9 09 00 00 8b 55 f0 81 f2 00 00 00 99 89 15 ?? ?? 42 00 8b 05 ?? ?? 43 00 f7 d0 05 ?? ?? 00 00 c1 e8 ?? 89 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EyeStye_N_2147645167_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye.N"
        threat_id = "2147645167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 b8 5c 3f 3f 5c c6 45 bc 00 89 85 54 ff ff ff e8 00 00 00 00 58 89 45 f8 8b 45 f8 8b d0 81 e2 ff 0f 00 00 33 c9 2b c2 41 05 20 0b 00 00 81 38 21 45 59 45 8b f8}  //weight: 1, accuracy: High
        $x_1_2 = {51 68 65 24 58 6a 6a 03 e8 ?? ?? ?? ff 59}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7d 08 03 75 2b 8b 06 3d 6e 74 64 6c 74 07 3d 4e 54 44 4c 75 1b 64 a1 30 00 00 00 8b 40 0c}  //weight: 1, accuracy: High
        $x_1_4 = {3d 33 8a 04 43 0f 84 ?? ?? ?? ?? 39 7d e0 74 14 3d 72 09 0a 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EyeStye_C_2147645536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye.gen!C"
        threat_id = "2147645536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 69 6e 6d 6d 2e 64 6c 6c [0-4] 6f 76 67 70 71 34 6b 74 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EyeStye_2147645556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147645556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 63 74 69 76 65 41 5a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "var _aaz_rez = 1;" ascii //weight: 1
        $x_1_3 = {6a 00 6a 00 6a 03 6a 00 6a 00 68 bb 01 00 00 8d 4d c0 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EyeStye_2147645556_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147645556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\pipe\\presp%d" ascii //weight: 1
        $x_1_2 = "turn off proactive\\antivirus." ascii //weight: 1
        $x_1_3 = "TakeBotGuid" ascii //weight: 1
        $x_1_4 = "RdpGetLastError" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_EyeStye_2147645556_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147645556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 65 79 6c 6f 67 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 6f 63 6b 73 2e 64 6c 6c 00 43 61 6c 6c 62 61 63 6b}  //weight: 1, accuracy: High
        $x_1_3 = {54 61 6b 65 42 6f 74 47 75 69 64 00 54 61 6b 65 47 61 74 65}  //weight: 1, accuracy: High
        $x_1_4 = "cacert.pem" wide //weight: 1
        $x_1_5 = "grabkeys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_EyeStye_2147645556_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147645556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "150 Opening BINARY mode data connection" ascii //weight: 1
        $x_1_2 = "ftpbc.dll" ascii //weight: 1
        $x_1_3 = "-rw-r--r-- 1 0 0 " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EyeStye_2147645556_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147645556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FF ; %s ; %s ; %s" ascii //weight: 1
        $x_1_2 = "spyEYE" ascii //weight: 1
        $x_1_3 = "\\Mozilla\\Firefox\\profiles.ini" ascii //weight: 1
        $x_1_4 = "TakeBotGuid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EyeStye_2147645556_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147645556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 07 63 f5 53 66 c7 44 24 ?? bf b6}  //weight: 1, accuracy: Low
        $x_1_2 = {7f d5 c6 44 3e fe 0d c6 44 3e ff 0a c6 04 3e 00}  //weight: 1, accuracy: High
        $x_2_3 = "*forum*newreply.php*" ascii //weight: 2
        $x_2_4 = {73 70 79 53 70 72 65 61 64 2e 64 6c 6c 00 43 61 6c 6c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EyeStye_2147645556_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147645556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "name=\"seckey\"" ascii //weight: 1
        $x_1_2 = {3f 70 6c 5f 6e 61 6d 65 3d [0-8] 26 75 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "datashit=" ascii //weight: 1
        $x_1_4 = {8b f0 81 7d fc c8 00 00 00 76 ?? 8b [0-21] 8b c6 e8 ?? ?? ?? ?? 8b f8 8d ?? ?? 50 8b cf ba 50 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_EyeStye_2147645556_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147645556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 6e 69 74 00 53 74 61 72 74 00 53 74 6f 70}  //weight: 1, accuracy: High
        $x_1_2 = "TakeBotGuid" ascii //weight: 1
        $x_1_3 = "TakeGateToCollector" ascii //weight: 1
        $x_1_4 = "TakeGetPage" ascii //weight: 1
        $x_1_5 = "bot_guid" ascii //weight: 1
        $x_1_6 = "Callback_OnBeforeProcessUrl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_EyeStye_2147645556_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147645556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TakeGateToCollector3" ascii //weight: 1
        $x_1_2 = "yA36zA48dEhfrvghGRg57h5UlDv3" wide //weight: 1
        $x_1_3 = {73 6f 66 74 77 61 72 65 67 72 61 62 62 65 72 2e 64 6c 6c 00 49 6e 69 74 00 53 74 61 72 74 00 53 74 6f 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EyeStye_2147645556_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147645556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "guid=%s&ver=%u&ie=%s&os=%u.%u.%u&ut=%s&ccrc=%08X&md5=%s&plg=%s" ascii //weight: 1
        $x_1_2 = "MainCpGateInput" ascii //weight: 1
        $x_1_3 = "customconnector.dll" ascii //weight: 1
        $x_1_4 = "TakeBotGuid" ascii //weight: 1
        $x_1_5 = "%s&stat=online" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_EyeStye_2147645556_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye"
        threat_id = "2147645556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TakeBotGuid" ascii //weight: 1
        $x_1_2 = "TakeGateToCollector" ascii //weight: 1
        $x_1_3 = {8b 45 08 80 3c 01 3b 75 03}  //weight: 1, accuracy: High
        $x_1_4 = {6a 11 6a 02 6a 02 e8 31 0e 00 00 89 84 b5 08 e5 ff ff 83 f8 ff 74 12 8d 8d 64 e3 ff ff 51 68 7e 66 04 80 50}  //weight: 1, accuracy: High
        $x_1_5 = "raiffeisen.ru/rba/" ascii //weight: 1
        $x_1_6 = {83 f8 23 0f 84 29 01 00 00 83 f8 3b 0f 84 20 01 00 00 6a 5b 57 e8 ?? ?? ?? ?? 83 c4 08}  //weight: 1, accuracy: Low
        $x_1_7 = {8d 0c 02 8a 01 0f be f0 81 fe db 00 00 00 74 04 34 db 88 01}  //weight: 1, accuracy: High
        $x_1_8 = "guid=%s&ver=%u&ie=%s&os=%u.%u.%u&ut=%s&ccrc=%08X&md5=%s&plg=%s&wake=%u" ascii //weight: 1
        $x_1_9 = "justreplace=" ascii //weight: 1
        $x_1_10 = "entry \"JabberNotifier\"" ascii //weight: 1
        $x_3_11 = "SpyEye\\plugins" ascii //weight: 3
        $x_3_12 = "SpyEye_Start" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EyeStye_U_2147647113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye.U"
        threat_id = "2147647113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cleansweep.exe" ascii //weight: 1
        $x_1_2 = "__SPYNET" ascii //weight: 1
        $x_1_3 = "-%BOTNAME%" ascii //weight: 1
        $x_1_4 = {63 6f 6f 6b 69 65 73 2d [0-8] 74 6f 72 2e 78 6d 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EyeStye_D_2147647317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye.gen!D"
        threat_id = "2147647317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 08 ff 15 ?? ?? ?? ?? 50 06 1c ff 03 b0 f6 5d c3 33 c0 03 20 83 7d 08 00 74 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EyeStye_AK_2147658791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye.AK"
        threat_id = "2147658791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c3 8b 45 0c 3d ?? ?? 00 00 75 ?? 8b 45 08 b9 ?? 00 00 00 f2 35 ?? ?? ?? ?? ff d0 03 00 ?? f0}  //weight: 10, accuracy: Low
        $x_2_2 = {0f b6 5c 15 00 45 83 fd 0f 75 05 bd 00 00 00 00 46 30 1f 47 3b f1 72 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EyeStye_AEYE_2147939905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EyeStye.AEYE!MTB"
        threat_id = "2147939905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {08 00 a4 00 a2 ?? ?? ?? ?? e0 cb 00 00 94 08 00 a4 00 a2 ?? ?? ?? ?? e1 cb 00 00 94 08 00 a4 00 a2 ?? ?? ?? ?? e2 cb 00 00 94 08 00 a4}  //weight: 3, accuracy: Low
        $x_2_2 = "TFONILAKlQEYetLfZYoE" ascii //weight: 2
        $x_1_3 = "kEYedSMuZpDwVKUWPOIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


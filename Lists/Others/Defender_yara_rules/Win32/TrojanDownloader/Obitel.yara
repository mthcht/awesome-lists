rule TrojanDownloader_Win32_Obitel_A_2147609622_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obitel.A"
        threat_id = "2147609622"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obitel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fixaserver.ru" ascii //weight: 1
        $x_1_2 = "ldr2/gate.php" ascii //weight: 1
        $x_1_3 = "hash=" ascii //weight: 1
        $x_1_4 = "QueueUserAPC" ascii //weight: 1
        $x_1_5 = "userini.exe" ascii //weight: 1
        $x_1_6 = {53 55 56 57 33 ed 55 55 55 68 ?? ?? ?? ?? 55 55 ff 15 ?? ?? 40 00 8b ?? ?? ?? ?? ?? 55 8b f0 56 68 ?? ?? ?? ?? ff d7 8b ?? ?? ?? ?? ?? 55 68 ec 00 00 00 ff d3 55 56 68 ?? ?? ?? ?? ff d7 56 ff 15 ?? ?? 40 00 6a 01 6a ff ff d3 5f 5e 5d 33 c0 5b c2 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Obitel_A_2147611049_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obitel.gen!A"
        threat_id = "2147611049"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obitel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 75 f8 33 c0 8a 4c 05 ?? 80 c1 07 00 4c 35 ?? 40 83 f8 15 72 02 33 c0 46 83 fe 0b}  //weight: 2, accuracy: Low
        $x_1_2 = {7f 03 80 c1 20 8b da 0f a4 fa 0f 33 ed 0f be c1 0b ea c1 eb 11 c1 e7 0f 99}  //weight: 1, accuracy: High
        $x_1_3 = {eb 11 8b 5d fc 0f be d2 c1 c3 0d 33 da 47 8a 17 89 5d fc 84 d2 75 eb}  //weight: 1, accuracy: High
        $x_2_4 = {3d 38 23 f1 d0 75 ?? 81 fa f9 39 9d a1 75}  //weight: 2, accuracy: Low
        $x_1_5 = {c7 04 24 73 8d c7 26}  //weight: 1, accuracy: High
        $x_3_6 = {8a 00 3c 3b 74 2d 3a c3 74 29 3c 0d 74 25 3c 0a 74 21 8b 4f 0c 00 0f 83}  //weight: 3, accuracy: Low
        $x_3_7 = {8b 08 50 ff 51 1c 85 c0 7c 4d eb 17 8d 86 ?? ?? 00 00 8b 08 83 f9 01 74 05 83 f9 02 75 1e}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Obitel_B_2147611050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obitel.B"
        threat_id = "2147611050"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obitel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "131"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {80 f9 41 7c 08 80 f9 5a 7f 03 80 c1 20 8b da 0f a4 fa 0f 33 ed 0f be c1 0b ea c1 eb 11 c1 e7 0f 99 0b df 33 d8 33 ea 46 8a 0e 8b fb 8b d5 84 c9 75 ce}  //weight: 100, accuracy: High
        $x_10_2 = "fixaserver.ru" ascii //weight: 10
        $x_10_3 = "ldr/gate.php" ascii //weight: 10
        $x_10_4 = "sfc_os.dll" ascii //weight: 10
        $x_1_5 = "\\userini.exe" ascii //weight: 1
        $x_1_6 = "\\userinit.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Obitel_C_2147611125_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obitel.C"
        threat_id = "2147611125"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obitel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 38 6e 74 1f 80 bf ?? ?? 00 00 6f 74 16 80 bf ?? ?? 00 00 6e 74 0d 80 bf ?? ?? 00 00 65 74 04 50 ff 57}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 c1 e8 1c 3c 0a 0f b6 c0 73 05 83 c0 30 eb 03 83 c0 57 c1 65 08 04 88 04 0a 42 83 fa 08 7c de}  //weight: 1, accuracy: High
        $x_1_3 = {3f 68 61 73 68 3d 00 00 68 74 74 70 3a 2f 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Obitel_B_2147611718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obitel.gen!B"
        threat_id = "2147611718"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obitel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7f 03 80 c1 20 8b da 0f a4 fa 0f 33 ed 0f be c1 0b ea c1 eb 11 c1 e7 0f 99}  //weight: 1, accuracy: High
        $x_1_2 = {eb 11 8b 5d fc 0f be d2 c1 c3 0d 33 da 47 8a 17 89 5d fc 84 d2 75 eb}  //weight: 1, accuracy: High
        $x_1_3 = {6a 01 68 87 07 00 00 ff 15 ?? ?? 40 00 eb f1}  //weight: 1, accuracy: Low
        $x_1_4 = "QueueUserAPC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Obitel_C_2147621292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obitel.gen!C"
        threat_id = "2147621292"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obitel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 07 3d 68 74 74 70 75}  //weight: 2, accuracy: High
        $x_1_2 = {32 f2 88 33 43}  //weight: 1, accuracy: High
        $x_1_3 = {8a 21 32 e0 88 21}  //weight: 1, accuracy: High
        $x_1_4 = {8a 02 83 f0 00 3d cc 00 00 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Obitel_D_2147622846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obitel.D"
        threat_id = "2147622846"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obitel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://mabira.net/traff/controller.php?&ver=8&uid=" wide //weight: 1
        $x_1_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 00 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 00 00 5c 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {e8 52 0c 00 00 85 c0 74 28 8d 94 24 24 01 00 00 68 0c 83 41 00 52 e8 ec 1d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Obitel_E_2147622880_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obitel.E"
        threat_id = "2147622880"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obitel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://mabira.net/traff/controller.php?&ver=10&uid=" wide //weight: 1
        $x_1_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 00 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 00 00 5c 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {e8 52 0c 00 00 85 c0 74 28 8d 94 24 24 01 00 00 68 30 83 41 00 52 e8 4c 20 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Obitel_D_2147622881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obitel.gen!D"
        threat_id = "2147622881"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obitel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://mabira.net/traff/controller.php?&ver=" wide //weight: 1
        $x_1_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 00 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 00 00 5c 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {e8 52 0c 00 00 85 c0 74 28 8d 94 24 24 01 00 00 68 ?? ?? 41 00 52 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


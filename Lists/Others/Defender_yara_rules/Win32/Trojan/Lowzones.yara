rule Trojan_Win32_Lowzones_GT_116820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lowzones.GT"
        threat_id = "116820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lowzones"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff b4 24 28 1a 00 00 8d 84 24 28 02 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 83 c4 10 53 8d 44 24 14 50 53 68 3f 00 0f 00 53 53 53 8d 84 24 40 02 00 00 50 68 01 00 00 80}  //weight: 1, accuracy: Low
        $x_1_2 = {53 8d 44 24 14 50 53 68 3f 00 0f 00 53 53 53 68 ?? ?? ?? ?? 68 01 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? 00 00 68 04 01 00 00 8d 44 24 20 50 6a ff ff b4 24 34 1a 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 c7 44 24 14 3c 00 00 00 c7 44 24 1c 00 00 00 00 c7 44 24 20 ?? ?? ?? ?? ff d6 85 c0 6a 00 74 16}  //weight: 1, accuracy: Low
        $x_1_4 = {89 65 e8 c6 45 e7 01 c7 45 fc 00 00 00 00 52 51 53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Lowzones_GU_122425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lowzones.GU"
        threat_id = "122425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lowzones"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b3 01 8b c7 e8 ?? ?? ?? ff 8b f3 81 e6 ff 00 00 00 8b 55 fc 8a 54 32 ff [0-3] 88 54 30 ff 43 fe 4d fb 75 ?? 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 f7 01 8b 45 f8 e8 ?? ?? ?? ff 33 d2 8a 55 f7 33 c9 8a 4d f7 8b 5d fc 8a 4c 0b ff [0-3] 88 4c 10 ff fe 45 f7 fe 4d f6 75 ?? 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 6a 02 6a 01 8b 0d ?? ?? 42 00 8b 09 b2 01 a1 ?? ?? 42 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Lowzones_F_125888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lowzones.gen!F"
        threat_id = "125888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lowzones"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {68 01 16 00 00 57 56 ff 51 20 8b 06 53 6a 04 8d 4c 24 14 51 68 00 1c 00 00 57 56 c7 44 24 24 00 00 03 00 ff 50 20}  //weight: 3, accuracy: High
        $x_1_2 = {63 00 64 00 6e 00 2e 00 69 00 6d 00 61 00 67 00 65 00 73 00 72 00 76 00 72 00 2e 00 63 00 6f 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 00 64 00 6e 00 2e 00 69 00 6d 00 61 00 67 00 65 00 73 00 65 00 72 00 76 00 72 00 2e 00 63 00 6f 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 00 79 00 73 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lowzones_DZ_164767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lowzones.DZ"
        threat_id = "164767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lowzones"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "<script> for (i=0; i<document.links.length; i++) {var str=document.links(i).href;if (str.indexOf(\"/aclk\")!=-1){alert(document.links(i).href);break;}}</script>" ascii //weight: 10
        $x_10_2 = {3c 62 6f 64 79 [0-4] 61 64 5f 75 72 6c}  //weight: 10, accuracy: Low
        $x_1_3 = "\\CurrentVersion\\Internet Settings\\Zones\\3" wide //weight: 1
        $x_1_4 = "LowRiskFileTypes" wide //weight: 1
        $x_1_5 = ".zip;.rar;.nfo;.txt;.exe;.bat;.com;.cmd;.reg;.msi;.htm;" wide //weight: 1
        $x_1_6 = "SaveZoneInformation" wide //weight: 1
        $x_1_7 = "RunInvalidSignatures" wide //weight: 1
        $x_10_8 = {43 00 68 00 65 00 63 00 6b 00 45 00 78 00 65 00 53 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65 00 73 00 00 00 00 00 6e 00 6f 00}  //weight: 10, accuracy: High
        $x_10_9 = {26 00 64 00 20 00 26 00 74 00 00 00 26 00 77 00 26 00 62 00 26 00 62 00 26 00 70 00}  //weight: 10, accuracy: High
        $x_5_10 = {68 74 74 70 3a 2f 2f [0-8] 2e 63 6f 6d 2f 63 6c 69 63 6b 2f 3f 73 3d [0-8] 26 63 3d}  //weight: 5, accuracy: Low
        $x_5_11 = "res://SimpleBrowserDemo.exe/#" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}


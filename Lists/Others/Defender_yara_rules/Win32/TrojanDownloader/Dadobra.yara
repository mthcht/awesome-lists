rule TrojanDownloader_Win32_Dadobra_BM_2147603698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dadobra.BM"
        threat_id = "2147603698"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dadobra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TERRA.COM.BRL23UOL.COM.BRDF90NAOVAIPEGAR6YAHOO.COM." ascii //weight: 1
        $x_1_2 = {51 b9 09 00 00 00 6a 00 6a 00 49 75 f9 87 4d fc 53 56 57 89 4d f4 89 55 f8 89 45 fc 8b 45 fc e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 83 7d f8 00 75 0d 8b 45 f4 e8 ?? ?? ?? ?? e9 e1 01 00 00 8d 45 e8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 ec e8 ?? ?? ?? ?? 8b 45 e8 e8 ?? ?? ?? ?? 89 45 f0 33 f6}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f8 8d 45 ec 50 89 7d d0 c6 45 d4 00 8d 55 d0 33 c9 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 85 c0 0f 8e 59 01 00 00 89 45 dc c7 45 e4 01 00 00 00 a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 8d 55 d0 33 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dadobra_BN_2147609243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dadobra.BN"
        threat_id = "2147609243"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dadobra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e8 1e ed ff ff 8b 55 f4 b8 c4 a4 41 00 e8 c5 99 fe ff 85 c0 7f 4c 8d 45 e8 8b d3 e8 7b 96 fe ff 8b 45 e8 8d 55 ec e8 f8 ec ff ff 8b 55 ec b8 d8 a4 41 00 e8 9f 99 fe ff 85 c0 7f 26 8d 45 e0 8b d3 e8 55 96 fe ff 8b 45 e0 8d 55 e4 e8 d2 ec ff ff 8b 55 e4 b8 ec a4 41 00 e8 79 99 fe ff 85 c0 7e 0b 33 db 6a 16 e8 58 aa fe ff eb 09 53 ff 15 8c c7 41 00}  //weight: 10, accuracy: High
        $x_1_2 = "Settings\\{FCADDC14-BD46-408A-9842-CDBE1C6D37EB" ascii //weight: 1
        $x_1_3 = "msapp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dadobra_BO_2147609244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dadobra.BO"
        threat_id = "2147609244"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dadobra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 7e 9b 41 00 64 ff 30 64 89 20 b8 4c b7 41 00 ba 94 9b 41 00 e8 fb 9d fe ff 6a 00 68 44 b7 41 00 68 38 95 41 00 8d 45 c0 50 b9 03 00 00 00 ba 01 00 00 00 a1 4c b7 41 00 e8 43 a2 fe ff 8d 45 c0 50}  //weight: 10, accuracy: High
        $x_1_2 = "SCPNEWCT.BIN" ascii //weight: 1
        $x_1_3 = "SCPNEURL.BIN" ascii //weight: 1
        $x_1_4 = "SCPNELOG.BIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dadobra_BR_2147626545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dadobra.BR"
        threat_id = "2147626545"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dadobra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 64 62 74 74 65 2e 63 6f 6d 2f 6e 74 74 65 2f 41 74 75 61 6c 69 7a 61 64 61 2e 65 78 65 [0-10] 63 6d 64 20 2f 6b 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 41 74 75 61 6c 69 7a 61 64 61 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 73 79 64 6c 2e 67 6f 76 2e 63 6e 2f 64 6c 7a 6a 2f 35 2f 35 33 2f 69 6d 67 2f 68 74 74 73 2e 65 78 65 [0-10] 63 6d 64 20 2f 6b 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 68 74 74 73 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dadobra_BS_2147627550_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dadobra.BS"
        threat_id = "2147627550"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dadobra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_2_2 = "190.34.136.180/" ascii //weight: 2
        $x_1_3 = "\\windowsupdate32.exe" ascii //weight: 1
        $x_1_4 = "\\handle32.exe" ascii //weight: 1
        $x_1_5 = "BootExecute" ascii //weight: 1
        $x_1_6 = "FROGSICE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


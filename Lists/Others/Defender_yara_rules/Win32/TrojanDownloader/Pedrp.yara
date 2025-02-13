rule TrojanDownloader_Win32_Pedrp_A_2147654976_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pedrp.A"
        threat_id = "2147654976"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pedrp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "down file success" ascii //weight: 1
        $x_1_2 = {3c 0d 74 04 3c 0a 75 08 c6 84 14 ?? 00 00 00 00 80 bc 14 00 00 00 00 2f 74 03 4a 79 dc}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d0 85 c0 74 0a c7 05 ?? ?? ?? ?? 00 00 00 00 56 8b 35 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 8b 0e 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 56 ff 51 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pedrp_B_2147657118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pedrp.B"
        threat_id = "2147657118"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pedrp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 68 13 00 00 20 56 89 6c 24 2c c7 44 24 34 04 00 00 00 ff d7 85 c0 74}  //weight: 1, accuracy: High
        $x_1_2 = {3d 94 01 00 00 74 ?? 3d 93 01 00 00 74 ?? 8d 54 24 ?? 8d 44 24 ?? 52 8d 4c 24 ?? 50 51 68 05 00 00 20 56 89 6c 24 24 c7 44 24 38 04 00 00 00 89 6c 24 3c ff d7}  //weight: 1, accuracy: Low
        $x_1_3 = "down file success" ascii //weight: 1
        $x_1_4 = "Internet connect error:%d" ascii //weight: 1
        $x_1_5 = "Avaliable data:%u bytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


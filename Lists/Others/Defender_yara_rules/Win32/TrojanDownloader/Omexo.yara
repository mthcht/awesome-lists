rule TrojanDownloader_Win32_Omexo_A_2147626894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Omexo.A"
        threat_id = "2147626894"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Omexo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 0b 8b 51 50 52 50 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 14 08 88 54 24 03 80 74 24 03 ?? c0 4c 24 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Omexo_B_2147631675_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Omexo.B"
        threat_id = "2147631675"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Omexo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 0b 8b 49 50 51 50 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {f7 d0 33 d2 f7 74 24 04 8b c2 c2 04 00}  //weight: 1, accuracy: High
        $x_1_3 = {3d 31 04 00 00 75 1b 6a 00 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


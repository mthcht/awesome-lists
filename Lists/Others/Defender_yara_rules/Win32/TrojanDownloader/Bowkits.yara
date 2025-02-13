rule TrojanDownloader_Win32_Bowkits_A_2147610503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bowkits.A"
        threat_id = "2147610503"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bowkits"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 74 2f 68 ?? ?? 40 00 a1 ?? ?? 40 00 50 e8 ?? ?? ff ff 85 c0 75 09 33 c0 a3 ?? ?? 40 00 eb 12 6a ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 00 2c 21 74 0e 04 fe 2c 02 72 08 2c 06 0f 85}  //weight: 1, accuracy: High
        $x_2_3 = {6b 69 77 69 62 6f 74 33 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_Win32_Ropenda_A_2147696516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ropenda.A"
        threat_id = "2147696516"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ropenda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 35 cc 00 00 00 8b 8d ?? ?? ff ff 03 8d ?? ?? ff ff 88 01 eb c2}  //weight: 1, accuracy: Low
        $x_1_2 = {25 73 3f 76 3d 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


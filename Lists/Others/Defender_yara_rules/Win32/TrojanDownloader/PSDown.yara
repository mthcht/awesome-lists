rule TrojanDownloader_Win32_PSDown_BSA_2147941451_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PSDown.BSA!MTB"
        threat_id = "2147941451"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PSDown"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "-command $" wide //weight: 1
        $x_1_2 = {2d 00 6a 00 6f 00 69 00 6e 00 20 00 24 00 [0-32] 5b 00 2d 00 31 00 2e 00 2e 00 2d 00 28 00 24 00 [0-32] 2e 00 6c 00 65 00 6e 00 67 00 74 00 68 00 29 00 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


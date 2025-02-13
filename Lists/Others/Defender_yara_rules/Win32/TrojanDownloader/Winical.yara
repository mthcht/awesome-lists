rule TrojanDownloader_Win32_Winical_A_2147601539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Winical.A"
        threat_id = "2147601539"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Winical"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {99 f7 7d f8 8b 45 10 0f be 14 10 33 ca 8b 45 fc 03 85 ?? ?? ff ff 88 08 eb b4}  //weight: 5, accuracy: Low
        $x_2_2 = {0c 7d 32 8b ?? 08 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


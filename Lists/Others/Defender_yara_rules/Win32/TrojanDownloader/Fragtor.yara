rule TrojanDownloader_Win32_Fragtor_ARAZ_2147936192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fragtor.ARAZ!MTB"
        threat_id = "2147936192"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 08 03 55 fc 0f be 02 33 45 0c 8b 4d 08 03 4d fc 88 01 eb d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


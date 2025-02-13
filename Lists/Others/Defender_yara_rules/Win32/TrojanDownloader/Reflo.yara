rule TrojanDownloader_Win32_Reflo_CCHT_2147903436_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Reflo.CCHT!MTB"
        threat_id = "2147903436"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Reflo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 47 85 a0 fd ff ff 6a 00 6a 00 50 68 ?? ?? ?? ?? 6a 00 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


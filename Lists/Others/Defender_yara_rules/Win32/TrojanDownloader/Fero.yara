rule TrojanDownloader_Win32_Fero_GXU_2147912210_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fero.GXU!MTB"
        threat_id = "2147912210"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fero"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 29 d0 83 f0 ?? 8d 05 ?? ?? ?? ?? 01 20 83 f0 ?? 48 89 d0 4a b9 02 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_LummaStealer_CCFF_2147898893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/LummaStealer.CCFF!MTB"
        threat_id = "2147898893"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ca 83 e2 ?? 0f b6 54 14 ?? 32 54 0e ?? 88 14 0e 8d 51 ?? 83 e2 ?? 0f b6 54 14 ?? 32 54 0e ?? 88 54 0e ?? 83 c1 ?? 39 c8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


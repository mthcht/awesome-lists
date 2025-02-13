rule TrojanDownloader_Win32_Krap_SIB_2147817321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Krap.SIB!MTB"
        threat_id = "2147817321"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Krap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e7 8b 4f 04 01 ca 89 d0 40 8b 10 81 ea ?? ?? ?? ?? [0-16] 74 ?? eb ?? [0-10] 8b 54 24 04 31 c0 81 c0 ?? ?? ?? ?? 03 34 24 01 d0 [0-10] 8b 30 [0-10] 01 d6 29 c0 81 e8 2b 56 ed 6d 31 06 [0-10] 56 01 ef c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


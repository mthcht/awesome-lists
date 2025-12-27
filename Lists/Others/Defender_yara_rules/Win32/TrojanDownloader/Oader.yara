rule TrojanDownloader_Win32_Oader_ARA_2147957443_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Oader.ARA!MTB"
        threat_id = "2147957443"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Oader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {39 c3 7e 14 89 c2 83 e2 1f 8a 14 11 32 14 06 41 88 14 00 48 ff c0 eb e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


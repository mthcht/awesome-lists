rule TrojanDownloader_Win32_RookIE_ARA_2147920703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/RookIE.ARA!MTB"
        threat_id = "2147920703"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "RookIE"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 01 84 c0 74 09 34 08 46 88 04 0a 41 eb f1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_Pacrpt_YA_2147734368_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pacrpt.YA!MTB"
        threat_id = "2147734368"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pacrpt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://paste.ee/r/" ascii //weight: 1
        $x_1_2 = "\"yraniBoTgnirtStpyrC\\lld.23tpyrC\"" ascii //weight: 1
        $x_1_3 = "Base64dec( ByRef" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


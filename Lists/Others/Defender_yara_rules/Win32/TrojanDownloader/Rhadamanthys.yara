rule TrojanDownloader_Win32_Rhadamanthys_BB_2147905190_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rhadamanthys.BB!MTB"
        threat_id = "2147905190"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "textbin.net/raw/" ascii //weight: 10
        $x_10_2 = "ip-api.com/line/?fields=hosting" wide //weight: 10
        $x_1_3 = "api_log" ascii //weight: 1
        $x_1_4 = "dir_watch" ascii //weight: 1
        $x_1_5 = "vmcheck" ascii //weight: 1
        $x_1_6 = "snxhk" ascii //weight: 1
        $x_1_7 = "avghookx" ascii //weight: 1
        $x_1_8 = "avghooka" ascii //weight: 1
        $x_1_9 = "dbghelp" ascii //weight: 1
        $x_1_10 = "pstorec" ascii //weight: 1
        $x_1_11 = "cmdvrt64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


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
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "textbin.net/raw/" ascii //weight: 10
        $x_10_2 = "ip-api.com/line/?fields=hosting" wide //weight: 10
        $x_10_3 = {68 74 74 70 [0-1] 3a 2f 2f 74 2e 6d 65 2f}  //weight: 10, accuracy: Low
        $x_2_4 = "/c timeout /t 10 & rd /s /q \"C:\\ProgramData\\" ascii //weight: 2
        $x_2_5 = "\\Monero\\wallet.keys" ascii //weight: 2
        $x_2_6 = "\\BraveWallet\\Preferences" ascii //weight: 2
        $x_2_7 = "\\Discord\\tokens.txt" ascii //weight: 2
        $x_1_8 = "api_log" ascii //weight: 1
        $x_1_9 = "dir_watch" ascii //weight: 1
        $x_1_10 = "vmcheck" ascii //weight: 1
        $x_1_11 = "snxhk" ascii //weight: 1
        $x_1_12 = "avghookx" ascii //weight: 1
        $x_1_13 = "avghooka" ascii //weight: 1
        $x_1_14 = "dbghelp" ascii //weight: 1
        $x_1_15 = "pstorec" ascii //weight: 1
        $x_1_16 = "cmdvrt64" ascii //weight: 1
        $x_1_17 = "cmdvrt32" ascii //weight: 1
        $x_1_18 = "wpespy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


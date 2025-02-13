rule TrojanDownloader_Win32_Chindo_B_2147727447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chindo.B!bit"
        threat_id = "2147727447"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chindo"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "360Tray.exe" ascii //weight: 10
        $x_10_2 = "runAfterIstall" ascii //weight: 10
        $x_10_3 = "/report/tj_crashrecords.php" ascii //weight: 10
        $x_10_4 = "/res/minilogo2.ico" ascii //weight: 10
        $x_10_5 = "\"soft_id\":\"68\"" ascii //weight: 10
        $x_5_6 = "51bang5tapapy" ascii //weight: 5
        $x_5_7 = "!@#456$%^123" ascii //weight: 5
        $x_3_8 = "http://int.dpool.sina.com.cn/iplookup/iplookup.php" ascii //weight: 3
        $x_1_9 = "MessagePush" ascii //weight: 1
        $x_1_10 = "AutoUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Chindo_DEA_2147760004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chindo.DEA!MTB"
        threat_id = "2147760004"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chindo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_GifRecord_Muext_" ascii //weight: 1
        $x_1_2 = "zafeaf_ffaeaadfasdf" ascii //weight: 1
        $x_1_3 = "kjfahsf8ih999" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


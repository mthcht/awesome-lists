rule TrojanDownloader_Win32_GuLoader_SN_2147761523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GuLoader.SN!MTB"
        threat_id = "2147761523"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xylogra" ascii //weight: 1
        $x_1_2 = "Novicehoo" ascii //weight: 1
        $x_1_3 = "Outrang" ascii //weight: 1
        $x_1_4 = "Bocemenne" ascii //weight: 1
        $x_1_5 = "WIENERNES" ascii //weight: 1
        $x_1_6 = "Kvidis" ascii //weight: 1
        $x_20_7 = "MSVBVM60.DLL" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_GuLoader_SN_2147761523_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GuLoader.SN!MTB"
        threat_id = "2147761523"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_1_2 = "Fordansket" ascii //weight: 1
        $x_1_3 = "Sporangiolum" ascii //weight: 1
        $x_1_4 = "SPOROCHNUS" ascii //weight: 1
        $x_1_5 = "STORYWORK" ascii //weight: 1
        $x_1_6 = "OUTRIDERS" ascii //weight: 1
        $x_1_7 = "jointuring" ascii //weight: 1
        $x_1_8 = "udsugende" ascii //weight: 1
        $x_1_9 = "Unsisting" ascii //weight: 1
        $x_1_10 = "SANTINOMELMOZD" ascii //weight: 1
        $x_1_11 = "MiusyLaTroio" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}


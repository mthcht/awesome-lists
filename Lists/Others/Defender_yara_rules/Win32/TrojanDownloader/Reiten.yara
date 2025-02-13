rule TrojanDownloader_Win32_Reiten_2147633539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Reiten"
        threat_id = "2147633539"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Reiten"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://www.tier10.info/n2ivc.exe" ascii //weight: 2
        $x_1_2 = "\\ExecPri.dll" ascii //weight: 1
        $x_2_3 = "http://www.tier10.info/4rt66i.exe" ascii //weight: 2
        $x_1_4 = "\\iexpressa.exe" ascii //weight: 1
        $x_2_5 = "http://www.tier10.info/4cias.exe" ascii //weight: 2
        $x_1_6 = "\\GettingStarteda.exe" ascii //weight: 1
        $x_2_7 = "http://www.tier10.info/ecc.exe" ascii //weight: 2
        $x_2_8 = "http://www.tier10.info/s21aclt.exe" ascii //weight: 2
        $x_10_9 = "Nullsoft Install System" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}


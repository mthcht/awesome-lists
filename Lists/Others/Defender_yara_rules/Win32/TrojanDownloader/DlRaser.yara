rule TrojanDownloader_Win32_DlRaser_2147575124_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/DlRaser"
        threat_id = "2147575124"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "DlRaser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 04 07 65 c6 04 03 78 c6 04 28 65}  //weight: 2, accuracy: High
        $x_2_2 = ">> NUL /c del" ascii //weight: 2
        $x_2_3 = "/check.cgi?id=" ascii //weight: 2
        $x_1_4 = "Microsoft Internet Explorer" ascii //weight: 1
        $x_1_5 = "InternetOpen" ascii //weight: 1
        $x_1_6 = "ShellExecute" ascii //weight: 1
        $x_1_7 = "GetTempFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


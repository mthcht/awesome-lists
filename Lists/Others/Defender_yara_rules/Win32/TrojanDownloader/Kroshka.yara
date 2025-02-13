rule TrojanDownloader_Win32_Kroshka_A_2147620628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kroshka.A"
        threat_id = "2147620628"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kroshka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/babynot/" ascii //weight: 10
        $x_10_2 = "%u%d%u%d" ascii //weight: 10
        $x_10_3 = "xsxsmxax.exe" ascii //weight: 10
        $x_10_4 = "%s%s%s?%s=%s" ascii //weight: 10
        $x_10_5 = "IXXPLORE.EXE" ascii //weight: 10
        $x_10_6 = "CreazeProcessA" ascii //weight: 10
        $x_1_7 = "Microsoft Corporation All Rights Reserved" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}


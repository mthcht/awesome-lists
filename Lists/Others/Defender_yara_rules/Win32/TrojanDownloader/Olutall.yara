rule TrojanDownloader_Win32_Olutall_A_2147705630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Olutall.A"
        threat_id = "2147705630"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Olutall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "//ul.to/" wide //weight: 2
        $x_1_2 = "Internet Explorer_Server" wide //weight: 1
        $x_1_3 = "Welcome to Installer" wide //weight: 1
        $x_1_4 = "Install Your Software" wide //weight: 1
        $x_1_5 = "Setup1.exe" wide //weight: 1
        $x_1_6 = "/s /v/qn AGREETOLICENSE=yes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


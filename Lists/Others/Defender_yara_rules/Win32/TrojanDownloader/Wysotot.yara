rule TrojanDownloader_Win32_Wysotot_A_2147684219_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wysotot.A"
        threat_id = "2147684219"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wysotot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 0f 81 7d f8 50 4b 01 02 b8 99 ff ff ff 0f 45 d8 8b 3e 8d 55 f8 8b cf e8}  //weight: 2, accuracy: High
        $x_1_2 = "/DProtect.exe" ascii //weight: 1
        $x_1_3 = "/eGdpSvc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Wysotot_B_2147684714_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wysotot.B"
        threat_id = "2147684714"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wysotot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 0c 66 83 38 2d 74 12 83 c0 02 49 75 f4 5f 5b 83 c8 ff}  //weight: 1, accuracy: High
        $x_1_2 = "/eGdpSvc.exe" ascii //weight: 1
        $x_1_3 = "-url \"%s\" -f \"%s\" -exe \"%s\" -hide -uid %d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


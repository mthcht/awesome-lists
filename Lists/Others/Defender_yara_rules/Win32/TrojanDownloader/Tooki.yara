rule TrojanDownloader_Win32_Tooki_A_2147659111_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tooki.A"
        threat_id = "2147659111"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tooki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 07 8a 4f 01 88 44 24 0c 8a 47 02 88 4c 24 0d 8a 4f 03 3c 3d 88 44 24 0e 88 4c 24 0f 74 ?? 8b 54 24 0c 80 f9 3d}  //weight: 10, accuracy: Low
        $x_10_2 = {8a 46 01 33 db 3c 41 0f 9c c3 4b 83 e3 07 0f be d0 83 c3 30 2b d3 83 fa 10}  //weight: 10, accuracy: High
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "Network Location Awareness (NLA)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


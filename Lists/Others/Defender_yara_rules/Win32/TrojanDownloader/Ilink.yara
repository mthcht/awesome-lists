rule TrojanDownloader_Win32_Ilink_A_2147638905_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ilink.A"
        threat_id = "2147638905"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ilink"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 10
        $x_10_2 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List\\" ascii //weight: 10
        $x_10_3 = ":*:Enabled:" ascii //weight: 10
        $x_10_4 = "use MSIL code from this" ascii //weight: 10
        $x_10_5 = "URLDownloadToFileA" ascii //weight: 10
        $x_1_6 = "frlink.in" ascii //weight: 1
        $x_1_7 = {00 25 75 2e 25 75 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 3f 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 26 6f 73 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_Win32_Wadolin_A_2147622121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wadolin.A"
        threat_id = "2147622121"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wadolin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\pipe\\acsipc_server" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "%s:*:Enabled:%s" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f 00 2e 65 78 65 00 00 00 00 25 73 3f 76 3d 25 64 26 69 64 3d 25 78 2d 25 73}  //weight: 1, accuracy: High
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


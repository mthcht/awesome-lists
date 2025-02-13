rule Trojan_Win32_PowershellDownloader_RDB_2147838104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowershellDownloader.RDB!MTB"
        threat_id = "2147838104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowershellDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c \"powershell -command IEX(New-Object Net.Webclient).DownloadString('%s/%s')\"" wide //weight: 1
        $x_1_2 = "//e-hemsire.net/data/avatars" wide //weight: 1
        $x_1_3 = "%s/ab%d.php" wide //weight: 1
        $x_1_4 = "iuylu7lkuykuy" wide //weight: 1
        $x_1_5 = "config_20.ps1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PowershellDownloader_RDC_2147839572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowershellDownloader.RDC!MTB"
        threat_id = "2147839572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowershellDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c \"powershell -command IEX(New-Object Net.Webclient).DownloadString('%s/%s')\"" wide //weight: 1
        $x_1_2 = "/c ping 127.0.0.1 && del \"%s\" >> NUL" wide //weight: 1
        $x_1_3 = "//endsightconsulting.com/node_modules/acorn" wide //weight: 1
        $x_1_4 = "hfgkytk655434" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


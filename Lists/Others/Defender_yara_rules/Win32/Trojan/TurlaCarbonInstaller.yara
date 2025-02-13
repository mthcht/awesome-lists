rule Trojan_Win32_TurlaCarbonInstaller_B_2147849796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbonInstaller.B"
        threat_id = "2147849796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbonInstaller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pipe\\commctrldev" wide //weight: 1
        $x_1_2 = "pipe\\commsecdev" wide //weight: 1
        $x_1_3 = "installer.exe" ascii //weight: 1
        $x_1_4 = "Could not delete {}\\{}.sys" ascii //weight: 1
        $x_2_5 = "installer.pdb" ascii //weight: 2
        $x_2_6 = "/PUB/home.html" wide //weight: 2
        $x_2_7 = "cheapinfomedical99.net" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TurlaCarbonInstaller_C_2147849797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbonInstaller.C"
        threat_id = "2147849797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbonInstaller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36" wide //weight: 1
        $x_1_2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0" wide //weight: 1
        $x_1_3 = "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko" wide //weight: 1
        $x_2_4 = "C:\\Windows\\$NtUninstallQ608317$" wide //weight: 2
        $x_2_5 = "Set implant ID to " ascii //weight: 2
        $x_2_6 = "Shell Command: " ascii //weight: 2
        $x_2_7 = "Run as user: " ascii //weight: 2
        $x_2_8 = "Upload file" ascii //weight: 2
        $x_1_9 = "Global\\WinBaseSvcDBLock" wide //weight: 1
        $x_1_10 = "Global\\WindowsCommCtrlDB" wide //weight: 1
        $x_1_11 = "/IMAGES/3/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((5 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


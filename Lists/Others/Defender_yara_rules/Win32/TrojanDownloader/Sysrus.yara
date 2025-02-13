rule TrojanDownloader_Win32_Sysrus_A_2147741752_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sysrus.A"
        threat_id = "2147741752"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sysrus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\system32\\virus.exe" wide //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\virus" wide //weight: 1
        $x_1_3 = "f:/*.*" wide //weight: 1
        $x_1_4 = "F:/autorun.inf" wide //weight: 1
        $x_1_5 = "g:/*.*" wide //weight: 1
        $x_1_6 = "G:/autorun.inf" wide //weight: 1
        $x_1_7 = "WScript.Shell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


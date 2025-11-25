rule Trojan_Win32_SuspCertutil_A_2147958194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspCertutil.A"
        threat_id = "2147958194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCertutil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = ".ps1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


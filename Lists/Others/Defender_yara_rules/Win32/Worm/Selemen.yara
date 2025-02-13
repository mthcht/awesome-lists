rule Worm_Win32_Selemen_A_2147706561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Selemen.A"
        threat_id = "2147706561"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Selemen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows\\CurrentVersion\\Run\\svchost" wide //weight: 1
        $x_1_2 = ":\\Luna.exe" wide //weight: 1
        $x_1_3 = ":\\svchosta.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


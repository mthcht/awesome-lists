rule PWS_Win32_Bissldr_A_2147656094_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bissldr.A"
        threat_id = "2147656094"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bissldr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bssstealer_loader" ascii //weight: 1
        $x_1_2 = "PASSWORDS_IEXP" ascii //weight: 1
        $x_1_3 = "PC_INFO_GET" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


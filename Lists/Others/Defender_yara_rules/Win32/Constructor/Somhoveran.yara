rule Constructor_Win32_Somhoveran_A_2147695431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Constructor:Win32/Somhoveran.A"
        threat_id = "2147695431"
        type = "Constructor"
        platform = "Win32: Windows 32-bit platform"
        family = "Somhoveran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Warning! Windows Blocked!" ascii //weight: 1
        $x_1_2 = "Chanell:       youtube.com/user/MrDigitalInfection" ascii //weight: 1
        $x_1_3 = "Trojan.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Constructor_Win32_Sworm_A_2147649614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Constructor:Win32/Sworm.A"
        threat_id = "2147649614"
        type = "Constructor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sworm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(BlackBox) Stealth WoRm" ascii //weight: 1
        $x_1_2 = "Stealth WoRm Generated" ascii //weight: 1
        $x_1_3 = "Script by (BlackBox)" ascii //weight: 1
        $x_1_4 = ".WriteLine(\"%Setcode1%infect%Setcode1% c:\\windows\\%Setcode8% j:\\%Setcode1%target%Setcode1%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


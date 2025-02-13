rule Constructor_Win32_Bifrose_A_2147627102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Constructor:Win32/Bifrose.A"
        threat_id = "2147627102"
        type = "Constructor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BifrostSettings" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\BIFROST" ascii //weight: 1
        $x_1_3 = " Duty?A=iv1i" ascii //weight: 1
        $x_1_4 = "RECOMMENDATION: Bifrost will usually be better at bypassing firewalls if this is not used." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


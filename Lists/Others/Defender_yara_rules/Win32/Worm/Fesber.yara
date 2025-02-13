rule Worm_Win32_Fesber_G_2147679401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Fesber.G"
        threat_id = "2147679401"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Fesber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FSB-IS-MY-HEWRO" ascii //weight: 1
        $x_1_2 = "C:\\fsb.stb" ascii //weight: 1
        $x_1_3 = "\\notpad.exe" ascii //weight: 1
        $x_1_4 = "\\fsb.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


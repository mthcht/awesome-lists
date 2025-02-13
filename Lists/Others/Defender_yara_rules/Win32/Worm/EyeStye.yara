rule Worm_Win32_EyeStye_B_2147642147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/EyeStye.B"
        threat_id = "2147642147"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 06 3c 41 88 44 24 14 0f 84 89 00 00 00 3c 61 0f 84 81 00 00 00 3c 62 74 7d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ff d7 83 f8 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_EyeStye_B_2147642147_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/EyeStye.B"
        threat_id = "2147642147"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Basic USB Spread : Spreading \"%s\" As \"%s\"" ascii //weight: 1
        $x_1_2 = "Infected Drive(s)" ascii //weight: 1
        $x_1_3 = "%s\\autorun.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


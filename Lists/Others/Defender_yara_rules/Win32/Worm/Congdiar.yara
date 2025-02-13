rule Worm_Win32_Congdiar_A_2147631497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Congdiar.A"
        threat_id = "2147631497"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Congdiar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 46 fe 83 f8 04 77 2a ff 24 85 ?? ?? ?? ?? ba ?? ?? ?? ?? eb 21 ba ?? ?? ?? ?? eb 1a}  //weight: 1, accuracy: Low
        $x_1_2 = "Virus found !!!" wide //weight: 1
        $x_1_3 = ":\\Autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


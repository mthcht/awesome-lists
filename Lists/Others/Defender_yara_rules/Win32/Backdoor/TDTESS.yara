rule Backdoor_Win32_TDTESS_A_2147723366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/TDTESS.A!dha"
        threat_id = "2147723366"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "TDTESS"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "d2lubG9naW4l" wide //weight: 10
        $x_10_2 = "d2lubG9naW4k" wide //weight: 10
        $x_10_3 = "d2lubG9naW4q" wide //weight: 10
        $x_10_4 = "3D9B94A98B-76A8-4810-B1A0-4BE7C4F9C98DA2#" wide //weight: 10
        $x_20_5 = "C:\\Users\\admin\\Documents\\visual studio " ascii //weight: 20
        $x_20_6 = "\\TDTESS_ShortOne\\" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}


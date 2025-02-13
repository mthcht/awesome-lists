rule Virus_Win32_Cidu_A_2147601433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Cidu.A"
        threat_id = "2147601433"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Cidu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 10
        $x_10_2 = "Ur under attack u have the right to remain silent." ascii //weight: 10
        $x_10_3 = "me and my rc" ascii //weight: 10
        $x_10_4 = "The system shuts down in 60 seconds." ascii //weight: 10
        $x_1_5 = "Set cdaudio door open wait" ascii //weight: 1
        $x_1_6 = "Set cdaudio door closed wait" ascii //weight: 1
        $x_1_7 = "rundll32 keyboard,disable" ascii //weight: 1
        $x_1_8 = "rundll32 mouse,disable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule HackTool_Win32_IRCFlood_A_2147643234_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/IRCFlood.A"
        threat_id = "2147643234"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCFlood"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 66 6c 6f 6f 64 5f 73 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "FloodType=" wide //weight: 1
        $x_1_3 = "Icq Flooder by karas V" ascii //weight: 1
        $x_1_4 = "rundll32.exe shell32.dll,Control_RunDLL desk.cpl,,0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


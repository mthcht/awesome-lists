rule TrojanDropper_Win32_Zampol_A_2147727496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zampol.A!bit"
        threat_id = "2147727496"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zampol"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "decodage(bBuffer,srv)" ascii //weight: 1
        $x_1_2 = "TVqQAAMAAAAEAAAA" ascii //weight: 1
        $x_1_3 = "lib:=\"user32.dll\\CallWindowProcW\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


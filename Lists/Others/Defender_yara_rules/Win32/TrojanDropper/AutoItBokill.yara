rule TrojanDropper_Win32_AutoItBokill_2147697158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/AutoItBokill"
        threat_id = "2147697158"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoItBokill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0x4d5a90000300000004000000ffff0000" wide //weight: 1
        $x_1_2 = "@STARTUPDIR & \"\\\" & \"Windows\" & \".lnk\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


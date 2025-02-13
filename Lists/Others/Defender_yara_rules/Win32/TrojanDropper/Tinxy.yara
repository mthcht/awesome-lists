rule TrojanDropper_Win32_Tinxy_A_2147621436_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tinxy.A"
        threat_id = "2147621436"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a fc 50 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 04}  //weight: 1, accuracy: Low
        $x_1_2 = "S%st%se%scr%sf%sWi%sws\\%srr%sVe%son%sp%sre%sh%sl%sld%ss" ascii //weight: 1
        $x_1_3 = "%sser%sp%sf%sne%srk.%sox%sype%s1);" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


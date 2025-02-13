rule Rogue_Win32_Therlowindo_A_227815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Therlowindo.A"
        threat_id = "227815"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Therlowindo"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=%s&subID0=%d&mid=%s&user_ip=%s&win=%s&LTime=%lld&av=%s" ascii //weight: 1
        $x_1_2 = {00 5f 41 6e 74 69 56 69 72 75 73 3a 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\Mishel_Moviedea\\" ascii //weight: 1
        $x_1_4 = ".?AVCMonetizeThread@@" ascii //weight: 1
        $x_10_5 = "About WindoWeather" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


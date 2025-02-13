rule PWS_Win32_Yahmali_A_2147599699_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yahmali.A"
        threat_id = "2147599699"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahmali"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "-Caps Lock-" ascii //weight: 2
        $x_1_2 = "-Back-" ascii //weight: 1
        $x_1_3 = "SIGN IN" ascii //weight: 1
        $x_2_4 = "Yahoo! Messenger" ascii //weight: 2
        $x_2_5 = "index.php?text=" ascii //weight: 2
        $x_1_6 = "DUIViewWndClassName" ascii //weight: 1
        $x_2_7 = {66 3d 00 80 74 0d 6a 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Backdoor_Win32_Delrapca_A_2147622440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delrapca.A"
        threat_id = "2147622440"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delrapca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 39 00 75 06 8b 0d ?? ?? ?? ?? 8a 11 80 c2 17 30 10 41 40 4e 75 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 86 96 01 00 00 50 0f b6 86 95 01 00 00 50 0f b6 86 94 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "<br> Sys@User : %s@%s (%s)" ascii //weight: 1
        $x_1_4 = "%s?arg1=%s&arg2=%s&arg3=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win32_KaziBora_A_2147939984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/KaziBora.A!dha"
        threat_id = "2147939984"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "KaziBora"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = "Sycmentec" ascii //weight: 6
        $x_6_2 = {14 88 77 66 c7 [0-3] 08 02 00 00}  //weight: 6, accuracy: Low
        $x_2_3 = {03 77 66 55}  //weight: 2, accuracy: High
        $x_2_4 = {01 77 66 55}  //weight: 2, accuracy: High
        $x_2_5 = {11 88 77 66}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}


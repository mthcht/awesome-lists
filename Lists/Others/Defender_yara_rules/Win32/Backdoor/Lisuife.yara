rule Backdoor_Win32_Lisuife_A_2147694245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lisuife.A!dha"
        threat_id = "2147694245"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lisuife"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "is you live" ascii //weight: 5
        $x_1_2 = {b9 80 96 98 00 f7 f9 03 d3 52 e8 ?? ?? ?? ?? 83 c4 08 e8 ?? ?? ?? ?? 99 b9 60 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 80 96 98 00 f7 f9 03 f2 56 e8 ?? ?? ?? ?? 83 c4 04 e8 ?? ?? ?? ?? 99 b9 60 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Lisuife_B_2147694339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lisuife.B!dha"
        threat_id = "2147694339"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lisuife"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "176.31.112.10" ascii //weight: 1
        $x_1_2 = "is you live?" ascii //weight: 1
        $x_1_3 = "i`m wait" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


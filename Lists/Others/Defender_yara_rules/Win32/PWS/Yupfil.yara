rule PWS_Win32_Yupfil_A_2147647497_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yupfil.A"
        threat_id = "2147647497"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yupfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 46 10 00 10 00 00 89 5e 18 89 5e 1c 66 89 5e 20 66 89 5e 22 c7 46 24 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {6c 6c 7a 68 75 63 65 62 61 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Yupfil_B_2147647498_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yupfil.B"
        threat_id = "2147647498"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yupfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a d0 80 c2 01 30 90 ?? ?? ?? ?? 83 c0 01 83 f8 2e 72 ed}  //weight: 2, accuracy: Low
        $x_1_2 = "?d10=%s&d71=%s&d81=%s&d82" ascii //weight: 1
        $x_1_3 = "?d01=%s&d10=%s" ascii //weight: 1
        $x_2_4 = {c7 07 0c 00 00 00 e8 ?? ?? ?? ?? 83 c3 01 83 c7 14 3b 1e 7c ea}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


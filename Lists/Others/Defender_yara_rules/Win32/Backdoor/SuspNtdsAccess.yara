rule Backdoor_Win32_SuspNtdsAccess_B_2147961712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/SuspNtdsAccess.B!hva"
        threat_id = "2147961712"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspNtdsAccess"
        severity = "Critical"
        info = "hva: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\ntdsutil.exe" wide //weight: 10
        $x_10_2 = "ifm" wide //weight: 10
        $x_10_3 = " ntds" wide //weight: 10
        $x_1_4 = {63 00 72 00 20 00 66 00 75 00 [0-6] 63 00 3a 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {63 00 72 00 65 00 61 00 74 00 65 00 20 00 66 00 75 00 [0-6] 63 00 3a 00 5c 00}  //weight: 1, accuracy: Low
        $n_100_6 = ":\\ifm" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


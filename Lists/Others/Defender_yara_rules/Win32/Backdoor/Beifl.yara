rule Backdoor_Win32_Beifl_B_2147683054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Beifl.B"
        threat_id = "2147683054"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Beifl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 44 44 ?? 6c 00 66 c7 44 44 ?? 6e 00 66 c7 44 44 ?? 6b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {66 c7 84 45 ?? ?? ff ff 6c 00 66 c7 84 45 ?? ?? ff ff 6e 00 66 c7 84 45 ?? ?? ff ff 6b 00}  //weight: 1, accuracy: Low
        $x_2_3 = {8a 07 3c 11 76 63 25 ff 00 00 00 83 e8 11 47}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


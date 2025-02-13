rule Backdoor_Win32_Fledrots_A_2147641429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fledrots.A"
        threat_id = "2147641429"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fledrots"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 70 f1 00 00 68 12 01 00 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? eb cd}  //weight: 2, accuracy: Low
        $x_1_2 = "ping.php" ascii //weight: 1
        $x_1_3 = {69 6d 67 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = "&rst=1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Wingbird_C_2147723909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wingbird.C!dha"
        threat_id = "2147723909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wingbird"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c0 58 0f 84 ?? ?? ?? ?? cc cc cc cc cc 8b ff 55 8b ec}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c9 59 0f 84 ?? ?? ?? ?? cc cc cc cc cc 8b ff 55 8b ec}  //weight: 1, accuracy: Low
        $x_1_3 = {31 d2 5a 0f 84 ?? ?? ?? ?? cc cc cc cc cc 8b ff 55 8b ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


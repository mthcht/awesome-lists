rule Worm_Win32_Kerm_A_2147652544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kerm.A"
        threat_id = "2147652544"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kerm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {54 5f 66 69 72 65 5f 74 61 73 6b ?? ?? ?? ?? ?? ?? ?? 54 5f 73 72 75 72 74 75 70}  //weight: 10, accuracy: Low
        $x_2_2 = {0c 6f 6e 65 5f 72 75 6e 54 69 6d 65 72}  //weight: 2, accuracy: High
        $x_1_3 = "keylog" ascii //weight: 1
        $x_1_4 = "keypress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


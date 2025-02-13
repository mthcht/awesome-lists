rule Ransom_Win32_Wannaren_A_2147753124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wannaren.A"
        threat_id = "2147753124"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wannaren"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = ".WannaRen" ascii //weight: 2
        $x_1_2 = {43 72 79 70 74 47 65 74 4b 65 79 50 61 72 61 6d 00 44 65 6c 65 74 65 46 69 6c 65 41 00 50 61 74 68 46 69 6e 64 46 69 6c 65}  //weight: 1, accuracy: High
        $x_1_3 = {41 ff ff ff 81 ?? 3f ff ff ff c1 ?? 0a 81 ?? ff 01 00 00 81 ?? ff 01 00 00 81 ?? ff 7f 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {75 50 80 7c ?? ?? 64 75 49 80 7c ?? ?? 6f 75 42 80 7c ?? ?? 62 75 3b 80 7c ?? ?? 65 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


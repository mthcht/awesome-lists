rule Ransom_Win32_Mehmehowi_A_2147691912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mehmehowi.A"
        threat_id = "2147691912"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mehmehowi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 50 ff [0-6] ff [0-6] eb ?? 50 ff}  //weight: 1, accuracy: Low
        $x_3_2 = {50 6a 00 6a 01 6a 13 ff 15 ?? ?? ?? ?? 8d 45 ?? 50 6a 06 6a 00 6a 00 6a 00 68 20 04 00 c0 ff 15}  //weight: 3, accuracy: Low
        $x_1_3 = {ff ff 6a 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


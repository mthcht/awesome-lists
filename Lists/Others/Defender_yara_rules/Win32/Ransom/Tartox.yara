rule Ransom_Win32_Tartox_A_2147706256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tartox.A"
        threat_id = "2147706256"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tartox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Tartarus Ransome Instructions</title>" ascii //weight: 1
        $x_1_2 = {25 30 38 6c 58 2d 25 30 34 68 58 2d 25 30 34 68 58 2d 25 30 32 68 68 58 25 30 32 68 68 58 2d 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 00}  //weight: 1, accuracy: High
        $x_1_3 = "Detox Rasnome" ascii //weight: 1
        $x_1_4 = "Detox Ransome Instructions" ascii //weight: 1
        $x_1_5 = "detoxransome@sigaint.org" ascii //weight: 1
        $x_1_6 = {50 6c 65 61 73 65 20 50 61 79 20 ?? 20 42 69 74 63 6f 69 6e 20 49 6d 6d 65 64 69 61 74 6c 65 79 20 48 65 61 64 20 4f 76 65 72 20 54 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


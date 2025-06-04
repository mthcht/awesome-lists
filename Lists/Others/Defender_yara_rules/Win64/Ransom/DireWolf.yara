rule Ransom_Win64_DireWolf_A_2147942757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/DireWolf.A"
        threat_id = "2147942757"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "DireWolf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 69 7a 65 20 3d 20 2c 20 74 ?? 69 6c 20 3d 20 2e 64 69 72 65 77 6f 6c 66 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 2e 66 75 6e 63 32 00 6d 61 69 6e 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


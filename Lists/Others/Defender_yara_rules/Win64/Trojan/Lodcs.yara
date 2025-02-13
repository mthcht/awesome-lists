rule Trojan_Win64_Lodcs_A_2147833928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lodcs.A"
        threat_id = "2147833928"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lodcs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 01 43 32 04 02 41 88 00 49 ff c0 3b f3 72}  //weight: 1, accuracy: High
        $x_1_2 = {c1 fa 02 8b c2 c1 e8 1f 03 d0 8b c6 ff c6 8d 0c 52 c1 e1 03 2b c1}  //weight: 1, accuracy: High
        $x_1_3 = {43 6f 6e 76 65 72 74 54 68 72 65 61 64 54 6f 46 69 62 65 72 [0-10] 56 69 72 74 75 61 6c 41 6c 6c 6f 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


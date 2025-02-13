rule Trojan_Win64_HurlyBurly_B_2147741599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HurlyBurly.B!dha"
        threat_id = "2147741599"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HurlyBurly"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {69 c0 83 00 00 00 0f be d2 48 ff c1 03 c2 0f b6 11 84 d2}  //weight: 2, accuracy: High
        $x_1_2 = {00 73 36 34 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 73 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_4 = {00 73 6b 69 6e 5f 6d 61 69 6e 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 73 6b 69 6e 5f 61 74 74 61 63 68 00}  //weight: 2, accuracy: High
        $x_2_6 = {00 73 6b 69 6e 5f 69 6e 73 74 61 6c 6c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


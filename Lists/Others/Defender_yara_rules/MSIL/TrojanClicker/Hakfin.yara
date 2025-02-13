rule TrojanClicker_MSIL_Hakfin_A_2147689494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Hakfin.A"
        threat_id = "2147689494"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hakfin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 61 00 63 00 6b 00 66 00 69 00 6e 00 69 00 74 00 79 00 2e 00 63 00 6f 00 6d 00 2f 00 7a 00 65 00 75 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 ?? ?? 77 00 65 00 62 00 79 00 74 00 62 00 31 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 61 00 63 00 6b 00 66 00 69 00 6e 00 69 00 74 00 79 00 2e 00 63 00 6f 00 6d 00 2f 00 6c 00 65 00 6e 00 67 00 74 00 68 00 2e 00 68 00 74 00 6d 00 6c 00 ?? ?? 3c 00 70 00 3e 00 ?? ?? 3c 00 2f 00 70 00 3e 00}  //weight: 1, accuracy: Low
        $x_1_3 = {26 00 71 00 75 00 6f 00 74 00 3b 00 ?? ?? 22 00 ?? ?? 26 00 23 00 33 00 39 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_4 = {42 72 6f 77 73 65 72 00 42 72 6f 77 73 65 72 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


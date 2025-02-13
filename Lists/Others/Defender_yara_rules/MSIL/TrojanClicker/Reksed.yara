rule TrojanClicker_MSIL_Reksed_A_2147683206_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Reksed.A"
        threat_id = "2147683206"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reksed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\"ids\\\":\\s*\\[\\s*" wide //weight: 1
        $x_1_2 = "Google\\Chrome\\User Data\\Default\\Extensions\\" wide //weight: 1
        $x_1_3 = "\\sedat.js" wide //weight: 1
        $x_1_4 = {00 67 65 74 5f 53 65 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanClicker_MSIL_Reksed_B_2147684576_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Reksed.B"
        threat_id = "2147684576"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reksed"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\"name\": \"SB Video Player\"," ascii //weight: 10
        $x_5_2 = {3c 69 66 72 61 6d 65 20 73 72 63 3d 27 2f 2f [0-20] 2f 72 65 6b 6c 61 6d 2f 37 32 38 78 39 30 2e 68 74 6d 6c}  //weight: 5, accuracy: Low
        $x_5_3 = {2f 2f 20 66 61 63 65 62 6f 6f 6b 20 70 6f 73 74 20 72 65 6b 6c 61 6d [0-64] 66 6f 72 28 73 3d 30 3b 73 3c 74 6f 70 6c 61 6d 45 6c 65 6d 65 6e 74 3b 73 2b 2b 29 7b}  //weight: 5, accuracy: Low
        $x_1_4 = "\\\"ids\\\":\\s*\\[\\s*" wide //weight: 1
        $x_1_5 = "Google\\Chrome\\User Data\\Default\\Extensions\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}


rule Ransom_Linux_Weaxor_A_2147948169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Weaxor.A!MTB"
        threat_id = "2147948169"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Weaxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/biweax.php" ascii //weight: 2
        $x_1_2 = ".rox" ascii //weight: 1
        $x_1_3 = "key_of_target" ascii //weight: 1
        $x_1_4 = "roxaew.txt" ascii //weight: 1
        $x_2_5 = {74 74 70 3a 2f 2f 77 65 61 78 6f 72 [0-85] 2e 6f 6e 69 6f 6e 2f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_Weaxor_B_2147959091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Weaxor.B!MTB"
        threat_id = "2147959091"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Weaxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/biweax.php" ascii //weight: 1
        $x_1_2 = "weax.txt" ascii //weight: 1
        $x_1_3 = "decyrption" ascii //weight: 1
        $x_1_4 = "RECOVERY INFORMATION.txt" ascii //weight: 1
        $x_1_5 = {74 74 70 3a 2f 2f 77 65 61 78 6f 72 [0-85] 2e 6f 6e 69 6f 6e 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


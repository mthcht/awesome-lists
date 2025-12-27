rule Trojan_Script_CosmicPulse_B_2147952835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Script/CosmicPulse.B!dha"
        threat_id = "2147952835"
        type = "Trojan"
        platform = "Script: "
        family = "CosmicPulse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-64] 2f 00 76 00 69 00 65 00 77 00 2e 00 70 00 68 00 70 00 3f 00 [0-32] 26 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


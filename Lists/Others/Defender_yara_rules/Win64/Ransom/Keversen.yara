rule Ransom_Win64_Keversen_PA_2147786699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Keversen.PA!MTB"
        threat_id = "2147786699"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Keversen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".onion" wide //weight: 1
        $x_1_2 = "!=READMY=!.txt" wide //weight: 1
        $x_1_3 = "YOUR NETWORK HAS BEEN COMPROMISED" wide //weight: 1
        $x_1_4 = "All your important files have been encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Keversen_PB_2147787389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Keversen.PB!MTB"
        threat_id = "2147787389"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Keversen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".onion" wide //weight: 1
        $x_1_2 = "been encrypted" wide //weight: 1
        $x_3_3 = "!=READMY=!.txt" wide //weight: 3
        $x_3_4 = "!=How_to_decrypt_files=!.txt" wide //weight: 3
        $x_3_5 = "How_to_decrypt_files.txt" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


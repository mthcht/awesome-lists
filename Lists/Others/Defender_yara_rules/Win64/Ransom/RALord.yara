rule Ransom_Win64_RALord_BB_2147939224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/RALord.BB!MTB"
        threat_id = "2147939224"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "RALord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RALord ransomware" ascii //weight: 1
        $x_1_2 = ".onion" ascii //weight: 1
        $x_1_3 = "please do not touch the files becouse we can't decrypt it if you touch it" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_RALord_A_2147940828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/RALord.A"
        threat_id = "2147940828"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "RALord"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Encryption failed: " ascii //weight: 5
        $x_5_2 = "Unsafe environment detected - delaying " ascii //weight: 5
        $x_1_3 = "RNOVA" ascii //weight: 1
        $x_1_4 = "Nova" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_RALord_B_2147940829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/RALord.B"
        threat_id = "2147940829"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "RALord"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 00 55 c6 85 ?? 01 00 00 aa c6 85 ?? 01 00 00 00 c6 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


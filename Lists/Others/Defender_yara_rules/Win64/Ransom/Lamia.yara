rule Ransom_Win64_Lamia_C_2147951951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lamia.C!MTB"
        threat_id = "2147951951"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lamia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "LamiaLoader Ransomware" ascii //weight: 10
        $x_5_2 = "LamiaLoaderSuccessfully encrypted" ascii //weight: 5
        $x_5_3 = "Wallet" ascii //weight: 5
        $x_5_4 = "Encryption failed for file" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


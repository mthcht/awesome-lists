rule Ransom_Win64_Crypmodng_C_2147952480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Crypmodng.C!MTB"
        threat_id = "2147952480"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Crypmodng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 ca 48 8d 05 ?? ?? ?? ?? 0f b6 04 02 44 89 c1 31 c1 48 8b 55}  //weight: 5, accuracy: Low
        $x_5_2 = {48 89 c1 e8 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 48 63 d0 48 8b 8d ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 49 89 c9 49 89 d0 ba 01 00 00 00 48 89 c1 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Crypmodng_ACR_2147952510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Crypmodng.ACR!MTB"
        threat_id = "2147952510"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Crypmodng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 28 48 8d 0d a5 34 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 c1 34 07 00 48 89 c1 ff 15 ?? ?? ?? ?? 48 8d 15 68 ff ff ff 48 85 c0 48 0f 44 c2 48 89 05 ca 97 05 00 48 83 c4 28 48 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


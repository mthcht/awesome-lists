rule Ransom_Win64_Chaos_CG_2147954703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Chaos.CG!MTB"
        threat_id = "2147954703"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Chaos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 c2 80 c2 ?? 32 04 0f 32 c1 88 04 0f 48 ff c1 48 81 f9 ?? ?? ?? ?? 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Chaos_PCO_2147954726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Chaos.PCO!MTB"
        threat_id = "2147954726"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Chaos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c8 48 8d 52 01 40 32 cf ff c0 30 4a ff 3b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


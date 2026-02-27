rule Ransom_Win64_Cryrar_SE_2147963839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cryrar.SE!MTB"
        threat_id = "2147963839"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryrar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 74 08 ?? c1 e6 ?? 4c 09 de 41 c1 e2 ?? 49 09 f2 41 c1 e0 ?? 4d 09 d0 4d 09 c8 4c 33 44 11 ?? 4c 89 84 0c ?? ?? ?? ?? 48 83 c1 ?? 48 83 f9 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = "lume informationsystem volume ingram files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


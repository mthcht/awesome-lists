rule Ransom_Win64_Paradise_MKV_2147845940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Paradise.MKV!MTB"
        threat_id = "2147845940"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 89 d5 41 33 78 ?? 45 33 7a ?? 45 33 5a ?? 03 4c 24 ?? 03 54 24 ?? 03 44 24 ?? 44 03 74 24 ?? 44 03 4c 24 ?? 44 8b 44 24 ?? 45 33 42 ?? 45 33 4a ?? 45 33 62 ?? 41 33 4d ?? 41 33 55 ?? 45 33 75 ?? 41 33 45 ?? 44 8b 54 24 ?? 45 33 55 ?? 83 44 24 ?? ?? 44 8b 6c 24 ?? 44 89 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = "Do not try to decrypt" ascii //weight: 1
        $x_1_3 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "Do not rename encrypted files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


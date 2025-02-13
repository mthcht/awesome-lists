rule Ransom_Win64_GhostLocker_YAA_2147896151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GhostLocker.YAA!MTB"
        threat_id = "2147896151"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Go build ID: \"" ascii //weight: 1
        $x_1_2 = "ALL YOUR FILES ARE" ascii //weight: 1
        $x_1_3 = "STOLEN AND ENCRYPTED!" ascii //weight: 1
        $x_1_4 = "ENCRYPTION ID:" ascii //weight: 1
        $x_1_5 = "assist you in decrypting" ascii //weight: 1
        $x_1_6 = "http://94.103.91.246/" ascii //weight: 1
        $x_1_7 = {49 83 c2 10 4c 8d 5b 01 4c 89 d3 4d 89 c1 49 89 f0 4c 89 de 48 39 f1 7e ?? 49 89 da 4c 8b 5b 08 4d 85 db 75 ?? 48 89 f3 4c 89 c6 4d 89 c8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


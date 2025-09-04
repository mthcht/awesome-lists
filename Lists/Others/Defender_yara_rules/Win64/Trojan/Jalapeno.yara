rule Trojan_Win64_Jalapeno_DA_2147920323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Jalapeno.DA!MTB"
        threat_id = "2147920323"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 55 73 65 72 73 5c 44 65 76 65 6c 6f 70 65 72 53 79 73 5c 44 6f 63 75 6d 65 6e 74 73 5c 45 6d 62 61 72 63 61 64 65 72 6f 5c 53 74 75 64 69 6f 5c 50 72 6f 6a 65 63 74 73 5c 44 4c 4c 20 4e 65 77 20 43 6f 6d 70 6c 65 74 61 5c 50 72 6f 6a 65 74 6f 20 43 2b 2b 5c [0-150] 5c 52 65 6c 65 61 73 65 5c [0-30] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Jalapeno_AB_2147951423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Jalapeno.AB!MTB"
        threat_id = "2147951423"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b7 09 48 b8 c5 4e ec c4 4e ec c4 4e 48 f7 e1 48 c1 ea 04 48 6b c2 34 48 2b c8 0f b7 44 4c 20 66 41 89 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


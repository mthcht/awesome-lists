rule Trojan_Win64_Poolinject_PGP_2147947496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Poolinject.PGP!MTB"
        threat_id = "2147947496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Poolinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {66 0f ef 4d f7 41 8b c8 66 48 0f 7e c8 48 89 75 07 48 89 7d 0f 66 0f ef 45 07 66 0f 7f 45 d7 66 0f 7f 4d c7 0f be d0 84 c0 74}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Poolinject_PGP_2147947496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Poolinject.PGP!MTB"
        threat_id = "2147947496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Poolinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 d1 30 c1 31 c0 28 c8 88 44 24 06 8b 4c 24 08 48 8b 54 24 18 44 8a 44 24 0f 8a 44 24 06 44 30 c0 4c 63 c1 42 88 04 02 83 c1 01 83 f9 1e 89 4c 24 28 88 44 24 2f 0f 85}  //weight: 5, accuracy: High
        $x_5_2 = {28 d1 30 c1 31 c0 28 c8 88 44 24 06 8b 4c 24 08 48 8b 54 24 18 44 8a 44 24 0f 8a 44 24 06 44 30 c0 4c 63 c1 42 88 04 02 83 c1 01 83 f9 08 89 4c 24 28 88 44 24 2f 0f 85}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Poolinject_PGLS_2147949499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Poolinject.PGLS!MTB"
        threat_id = "2147949499"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Poolinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 c6 89 f0 c1 e8 ?? 0f b6 ca 4c 8b 9c 24 ?? ?? ?? ?? 43 0f b6 14 03 31 ca 31 c2 31 f2 43 88 14 03 c1 c5 ?? 31 f5 45 01 d2 43 8d 0c 52 41 d3 e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


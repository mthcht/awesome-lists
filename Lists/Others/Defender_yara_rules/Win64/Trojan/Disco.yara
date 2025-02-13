rule Trojan_Win64_Disco_CM_2147908976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.CM!MTB"
        threat_id = "2147908976"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 4c 05 39 48 03 c7 48 83 f8 07 73 05 8a 4d 38 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Disco_SBB_2147931433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.SBB!MTB"
        threat_id = "2147931433"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 20 02 00 00 00 ff 15 df 1b 02 00 48 8b 3d f0 1c 02 00 49 89 c4 8a 03 48 ff c3 4d 89 e9 41 b8 01 00 00 00 48 c7 44 24 20 00 00 00 00 48 89 ea 4c 89 e1 83 f0 aa 88 44 24 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


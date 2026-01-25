rule Trojan_Win64_TransferLoader_GVA_2147961482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TransferLoader.GVA!MTB"
        threat_id = "2147961482"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TransferLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 0f af d3 4c 8b c2 4d 0f af c3 4a 8d 04 0a 4d 8b cb 48 03 c1 48 8b c8 48 c1 e0 20 48 c1 e9 20 48 0b c8 0f b7 c1 66 33 43 02 66 89 47 02 4a 8d 04 11}  //weight: 2, accuracy: High
        $x_1_2 = {41 8d 0c 00 69 d1 29 27 2e bf 45 8d 52 01 c1 ca 11 81 c2 29 27 2e bf 03 c2 c1 c8 0f 41 0f af c0 47 0f be 04 0a 03 c0 8b d0 c1 c8 0e c1 ca 10 45 85 c0 75 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_TransferLoader_GVB_2147961503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TransferLoader.GVB!MTB"
        threat_id = "2147961503"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TransferLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 44 24 ?? 48 83 f8 ?? 73 2f 48 63 44 24 24 0f b6 44 04 ?? 8b 4c 24 ?? c1 e1 03 48 8b 54 24 ?? 48 d3 ea 48 8b ca 0f b6 c9 33 c1 48 63 4c 24 24 88 84 0c ?? ?? ?? ?? eb a8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


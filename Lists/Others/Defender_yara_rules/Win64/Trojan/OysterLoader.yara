rule Trojan_Win64_OysterLoader_GVA_2147956935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OysterLoader.GVA!MTB"
        threat_id = "2147956935"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OysterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 0f 6e 44 04 ?? 66 0f 60 c0 66 0f 71 e0 08 66 0f d6 44 45 ?? 48 83 c0 04 48 3b c1 72 e2}  //weight: 2, accuracy: Low
        $x_1_2 = {0f be 4c 04 ?? 66 89 4c 45 ?? 48 ff c0 49 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


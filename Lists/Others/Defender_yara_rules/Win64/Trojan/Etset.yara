rule Trojan_Win64_Etset_GVA_2147941527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Etset.GVA!MTB"
        threat_id = "2147941527"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Etset"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 89 c2 66 2d c1 60 0f b6 c0 31 4d e4 29 55 e4 48 33 45 d2 48 ff 04 24 48 83 3c 24 07 7e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


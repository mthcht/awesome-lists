rule Trojan_Win64_Antiaris_A_2147906107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Antiaris.A!MTB"
        threat_id = "2147906107"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Antiaris"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 41 e7 30 44 0d ?? 48 ff c1 48 83 f9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


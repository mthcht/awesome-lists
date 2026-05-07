rule Trojan_Win64_GoObfus_C_2147968632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoObfus.C!MTB"
        threat_id = "2147968632"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoObfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 04 ?? 0f b6 74 04 ?? 31 f2 c0 c2 04 88 54 04 ?? 48 ff c0 48 83 f8 ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


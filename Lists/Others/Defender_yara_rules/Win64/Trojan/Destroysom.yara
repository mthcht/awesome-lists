rule Trojan_Win64_Destroysom_MBXW_2147921638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Destroysom.MBXW!MTB"
        threat_id = "2147921638"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Destroysom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 65 6b 46 34 76 41 42 78 6d 39 78 46 53 77 6c 30 6b 61 35 64 65 45 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


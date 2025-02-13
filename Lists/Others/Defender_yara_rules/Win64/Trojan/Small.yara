rule Trojan_Win64_Small_EM_2147898582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Small.EM!MTB"
        threat_id = "2147898582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 45 aa 48 8d 95 40 02 00 00 88 85 40 02 00 00 45 33 c9 0f b7 45 aa 44 8b c7 66 c1 e8 08 48 8b cb 88 85 41 02 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


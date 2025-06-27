rule Trojan_Win64_FatalRAT_GZZ_2147944875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FatalRAT.GZZ!MTB"
        threat_id = "2147944875"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FatalRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ff d3 c7 44 24 24 00 00 00 00 31 d2 89 d0 41 89 d0 8b 4c 24 24 41 c1 f8 02 83 e0 3f 41 0f af c0 44 6b c2 0d ff c2 44 31 c0 01 c8 81 fa f4 01 00 00 89 44 24 24}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_VAlleyRat_YBC_2147981381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VAlleyRat.YBC!MTB"
        threat_id = "2147981381"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VAlleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 b8 6b 65 72 6e 65 6c 33 32 48 89 44 24 ?? c7 44 24 38 2e 64 6c 6c}  //weight: 10, accuracy: Low
        $x_10_2 = {48 b8 6e 74 64 6c 6c 2e 64 6c 48 89 44 24 ?? 66 c7 44 24 48 6c 00}  //weight: 10, accuracy: Low
        $x_10_3 = {48 b8 72 61 72 79 43 61 6c 6c 48 89 44 24 ?? 66 c7 44 24 68 73 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


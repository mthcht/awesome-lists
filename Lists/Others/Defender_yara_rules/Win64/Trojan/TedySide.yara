rule Trojan_Win64_TedySide_YDR_2147972600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TedySide.YDR!MTB"
        threat_id = "2147972600"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TedySide"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 08 48 89 74 24 10}  //weight: 1, accuracy: High
        $x_1_2 = {41 56 56 57 53 48 83 ec 28 48 83 c4 28 5b 5f 5e 41 5e}  //weight: 1, accuracy: High
        $x_10_3 = {48 83 e9 01 05 00 48 83 e9 01 80 00 1f 48 ff c0 e9}  //weight: 10, accuracy: Low
        $x_10_4 = {48 83 e9 01 05 00 48 83 e9 01 80 00 1e 48 ff c0 e9}  //weight: 10, accuracy: Low
        $x_10_5 = {48 83 e9 01 05 00 48 83 e9 01 80 00 46 80 00 07 48 ff c0 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


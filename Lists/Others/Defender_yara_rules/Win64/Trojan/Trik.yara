rule Trojan_Win64_Trik_RS_2147965898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trik.RS!MTB"
        threat_id = "2147965898"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 40 18 48 8b 40 10 48 89 44 24 60 48 8b 44 24 60 48 8b 40 30 48 8b 4c 24 58 48 03 c8 48 8b c1 48 89 44 24 58 48 8b 44 24 58 48 89 44 24 50 ff 54 24 50}  //weight: 1, accuracy: High
        $x_1_2 = "test_results.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


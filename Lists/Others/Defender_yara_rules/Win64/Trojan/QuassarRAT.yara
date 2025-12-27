rule Trojan_Win64_QuassarRAT_ARR_2147954802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuassarRAT.ARR!MTB"
        threat_id = "2147954802"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuassarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {44 0f be 01 48 83 c1 01 41 01 d0 44 89 c2 c1 e2 07 44 01 c2 41 89 d0 41 c1 e8 06 44 31 c2 48 39 c8}  //weight: 30, accuracy: High
        $x_20_2 = {0f be 11 48 83 c1 01 01 c2 89 d0 c1 e0 07 01 d0 89 c2 c1 ea 06 31 d0 4c 39 c1}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_Resmusstealer_OD_2147978614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Resmusstealer.OD!MTB"
        threat_id = "2147978614"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Resmusstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 0f b6 14 10 45 31 c2 4c 8d 1c 80 45 31 d3 44 88 1c 02 48 ff c0 66 90 49 39 c1 7f e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


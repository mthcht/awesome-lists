rule Trojan_Win64_Swrort_CG_2147900577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Swrort.CG!MTB"
        threat_id = "2147900577"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Swrort"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 83 fa 0c 4d 8d 40 01 48 8b cf 48 0f 45 ca 41 ff c1 42 0f b6 04 39 48 8d 51 01 41 30 40 ff 49 63 c1 48 3b c3 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


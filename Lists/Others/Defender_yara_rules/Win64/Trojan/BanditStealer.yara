rule Trojan_Win64_BanditStealer_ABT_2147956099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BanditStealer.ABT!MTB"
        threat_id = "2147956099"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BanditStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 f2 88 54 24 42 0f b6 54 24 21 0f b6 74 24 2f 31 f2 88 54 24 43 0f b6 54 24 2c 0f b6 74 24 1b 29 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_Obsidium_AMBG_2147899965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Obsidium.AMBG!MTB"
        threat_id = "2147899965"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Obsidium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 5a 25 e5 ce 2f 84 d6 04 63 a4 56 cc 46 72 a2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


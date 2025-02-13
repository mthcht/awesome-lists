rule Trojan_Win64_Druid_DA_2147926690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Druid.DA!MTB"
        threat_id = "2147926690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Druid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 08 48 3b c1 73 ?? 48 63 04 24 48 8b 4c 24 30 0f be 04 01 0f be 0d ?? ?? ?? ?? 33 c1 48 63 0c 24 48 8b 54 24 30 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


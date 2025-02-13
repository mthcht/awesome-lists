rule Trojan_Win64_Prowloc_RPW_2147807731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Prowloc.RPW!MTB"
        threat_id = "2147807731"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Prowloc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 54 04 20 83 ea 09 88 54 04 20 48 ff c0 48 83 f8 09 72 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


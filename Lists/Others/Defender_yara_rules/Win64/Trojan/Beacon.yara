rule Trojan_Win64_Beacon_RDA_2147892587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Beacon.RDA!MTB"
        threat_id = "2147892587"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Beacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 e2 03 8a 54 15 00 41 32 14 04 88 14 03 48 ff c0 39 f8 89 c2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Beacon_RDB_2147902911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Beacon.RDB!MTB"
        threat_id = "2147902911"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Beacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 c1 83 e1 07 41 8a 0c 0a 41 30 0c 01 48 ff c0 eb e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


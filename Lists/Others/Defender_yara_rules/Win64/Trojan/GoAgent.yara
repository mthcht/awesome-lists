rule Trojan_Win64_GoAgent_AT_2147920879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoAgent.AT!MTB"
        threat_id = "2147920879"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c8 48 8d 54 24 70 49 89 dc 48 89 eb 48 c1 f8 3f 48 89 44 24 68}  //weight: 1, accuracy: High
        $x_1_2 = "TW96aWxsYS81LjAgK" ascii //weight: 1
        $x_1_3 = {48 85 c0 41 0f 9c c0 31 c9 48 89 c7 48 89 de 45 31 c9 31 c0 48 89 cb 0f 1f 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 c7 c7 08 00 fe 7f 48 8b 07 48 6b c0 64 48 89 44 24 08 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


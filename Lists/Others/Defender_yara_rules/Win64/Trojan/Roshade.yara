rule Trojan_Win64_Roshade_RPX_2147892700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Roshade.RPX!MTB"
        threat_id = "2147892700"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Roshade"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 30 00 00 00 48 8b 1d dc 48 03 00 48 8b 70 08 31 ed 4c 8b 25 3f c3 03 00 eb 16 0f 1f 44 00 00 48 39 c6 0f 84 1f 02 00 00 b9 e8 03 00 00 41 ff d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


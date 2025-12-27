rule Trojan_Win64_PurgeLogger_GVB_2147960148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PurgeLogger.GVB!MTB"
        threat_id = "2147960148"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PurgeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 08 00 00 06 28 02 00 00 0a 6f 03 00 00 0a 13 03 38 b6 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 00 00 fe 0c 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {28 13 00 00 06 7e 04 00 00 04 7e 05 00 00 04 28 09 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


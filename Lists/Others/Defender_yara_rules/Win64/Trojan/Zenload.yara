rule Trojan_Win64_Zenload_RA_2147838200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zenload.RA!MTB"
        threat_id = "2147838200"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 cc c0 e9 04 80 e1 03 0f b6 84 24 a8 00 00 00 c0 e0 02 02 c8 88 8c 24 a0 00 00 00 0f b6 84 24 aa 00 00 00 c0 e8 02 24 0f 41 c0 e4 04 41 32 c4 88 84 24 a1 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


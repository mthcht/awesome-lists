rule Trojan_Win64_Dllhijack_CCJW_2147938390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dllhijack.CCJW!MTB"
        threat_id = "2147938390"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dllhijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c6 8b ce c1 e0 06 c1 e9 08 33 c8 8b c7 83 e0 03 41 03 4c 85 00 03 ce 03 cf 43 29 4c 26 04 43 8b 44 26 04 43 89 04 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


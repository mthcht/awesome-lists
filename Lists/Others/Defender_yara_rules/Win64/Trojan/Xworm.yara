rule Trojan_Win64_Xworm_PGXS_2147948876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xworm.PGXS!MTB"
        threat_id = "2147948876"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c6 84 24 31 5a 00 00 68 c6 84 24 32 5a 00 00 43 c6 84 24 33 5a 00 00 33 c6 84 24 34 5a 00 00 34 c6 84 24 35 5a 00 00 68 c6 84 24 36 5a 00 00 78 c6 84 24 37 5a 00 00 51 c6 84 24 38 5a 00 00 72 c6 84 24 39 5a 00 00 4b c6 84 24 3a 5a 00 00 58 c6 84 24 3b 5a 00 00 34}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_Dukes_MA_2147849922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dukes.MA!MTB"
        threat_id = "2147849922"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dukes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {99 f7 f9 88 d0 88 44 24 07 48 8b 44 24 08 0f b7 4c 24 04 8a 04 08 88 44 24 03 48 8b 44 24 08 0f b6 4c 24 07 8a 14 08 48 8b 44 24 08 0f b7 4c 24 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


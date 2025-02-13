rule TrojanDropper_AndroidOS_Cerberus_F_2147812786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Cerberus.F!MTB"
        threat_id = "2147812786"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 04 13 07 0f 00 35 74 0a 00 97 05 08 09 93 07 05 09 b0 78 d8 04 04 01 ?? ?? 35 06 26 00 14 04 41 55 06 00 36 48 07 00 13 04 45 00 b0 95 b0 59 ?? ?? 13 04 e4 00 48 07 01 06 14 08 15 1e 06 00 b3 45 b0 85 b0 95 dc 08 06 03 48 08 03 08 ?? 09 05 04 97 04 07 08 8d 44 4f 04 02 06 ?? 08 09 05 d8 06 06 01 ?? ?? 71 30 ?? ?? 59 02 ?? ?? 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_AndroidOS_Sharkbot_A_2147837176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Sharkbot.A!MTB"
        threat_id = "2147837176"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Sharkbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 10 1e 01 05 00 0c 05 6e 20 ?? ?? 54 00 6e 20 ?? ?? 04 00 6e 10 ?? ?? 04 00 0c 04 71 30 78 16 43 01 0c 01 1a 03 ?? ?? 6e 30 c8 02 12 03 62 03 ?? ?? 6e 10 1d 01 03 00 0c 03 15 04 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {1a 00 41 09 6e 10 ?? ?? 07 00 0a 01 38 01 0d 00 52 70 ?? ?? 59 70 ?? ?? 6e 10 ?? ?? 07 00 6e 10 ?? ?? 07 00 0e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


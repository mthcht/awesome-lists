rule Trojan_AndroidOS_Loapi_A_2147830596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Loapi.A!MTB"
        threat_id = "2147830596"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Loapi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 31 2c 00 48 03 0b 01 ?? ?? ?? ?? ?? ?? 0b 04 84 44 48 04 0c 04 b7 43 8d 33 4f 03 00 01 ?? ?? ?? ?? ?? ?? 0b 04 16 06 01 00 bb 64 ?? ?? ?? ?? ?? ?? 0c 02 ?? ?? ?? ?? ?? ?? 0b 04 21 c3 81 36 31 03 04 06 3a 03 07 00 22 02 11 00 ?? ?? ?? ?? ?? ?? d8 01 01 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Loapi_B_2147840956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Loapi.B!MTB"
        threat_id = "2147840956"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Loapi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 31 2c 00 48 03 0b 01 6e 10 ?? ?? 02 00 0b 04 84 44 48 04 0c 04 b7 43 8d 33 4f 03 00 01 6e 10 ?? ?? 02 00 0b 04 16 06 01 00 bb 64 71 20 ?? ?? 54 00 0c 02 6e 10 ?? ?? 02 00 0b 04 21 c3 81 36 31 03 04 06 3a 03 07 00 22 02 12 00 70 30 ?? ?? 82 09 d8 01 01 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_AndroidOS_DroidRoot_T_2147794695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DroidRoot.T!MTB"
        threat_id = "2147794695"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DroidRoot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rageagainstthecage" ascii //weight: 1
        $x_1_2 = "z4root" ascii //weight: 1
        $x_1_3 = "chown root.root system/bin/su\\nchmod 6755 /system/bin/su\\n" ascii //weight: 1
        $x_10_4 = {00 12 0a 71 40 ?? ?? 98 7a 0c 03 1a 08 ?? 00 22 09 ?? 00 1a 0a ?? 00 70 20 ?? 00 a9 00 12 0a 44 0a 07 0a 6e 20 ?? ?? a9 00 0c 09 6e 10 ?? ?? 09 00 0c 09 71 20 ?? 00 98 00 22 05 ?? 00 70 20 ?? ?? 35 00 22 04 ?? 00 70 20 ?? ?? 34 00 22 08 ?? 00 70 30 ?? ?? b8 04 6e 10 ?? ?? 08 00 22 08 ?? 00}  //weight: 10, accuracy: Low
        $x_10_5 = {00 12 0b 71 40 ?? ?? a9 7b 0c 03 1a 09 ?? 00 22 09 ?? 00 1a 0a ?? 00 70 20 ?? ?? a9 00 12 0a 44 0a 07 0a 6e 20 ?? ?? a9 00 0c 09 6e 10 ?? ?? 09 00 0c 09 71 20 ?? 00 9c 00 22 05 ?? 00 70 20 ?? ?? 35 00 22 04 ?? 00 70 20 ?? ?? 34 00 22 09 ?? 00 70 40 ?? ?? d9 84 6e 10 ?? ?? 09 00 1a 00 ?? ?? 6e 10 ?? ?? 00 00 0c 09 6e 20 ?? ?? 95 00 6e 10 ?? ?? 05 00 15 09 04 7f 1a 0a ?? ?? 6e 10 ?? ?? 0d 00 0c 0b 71 30 ?? ?? a9 0b 14 09 02 00 04 7f 1a 0a ?? ?? 6e 10 ?? ?? 0d 00 0c 0b 71 30 ?? ?? a9 0b 14 09 03 00 04 7f 1a 0a ?? ?? 6e 10 ?? ?? 0d 00 0c 0b 71 30 ?? ?? a9 0b 22 09 ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


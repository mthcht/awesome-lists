rule Trojan_AndroidOS_Harly_A_2147831550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Harly.A!MTB"
        threat_id = "2147831550"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Harly"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1a 05 1a 53 71 20 0a 08 35 00 0c 05 38 00 07 00 6e 10 0f 03 00 00 0c 00 28 1c 1a 00 7d 6c 71 10 49 80 00 00 0c 00 71 10 d6 07 00 00 0a 06 38 06 03 00 28 0c 22 06 7e 19 70 20 17 7e 06 00 6e 10 20 7e 06 00 0a 00 39 00 04 00 07 40 28 02 07 60 39 00 03 00 28 64 22 06 7e 19 22 07 df 19 70 10 2a 80 07 00 71 00 47 80 00 00 0b 08 6e 30 32 80 87 09 1a 08 28 08 6e 20 36 80 87 00 6e 10 43 80 07 00 0c 07 70 30 16 7e 06 07}  //weight: 2, accuracy: High
        $x_2_2 = "sep.topsavor.site" ascii //weight: 2
        $x_1_3 = "persistedinstallation" ascii //weight: 1
        $x_1_4 = "com/barbarahenrietta/livewallpaper" ascii //weight: 1
        $x_1_5 = "isemulator" ascii //weight: 1
        $x_1_6 = "getApplicationAutoStart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Harly_B_2147833634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Harly.B!MTB"
        threat_id = "2147833634"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Harly"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a8 00 00 90 08 9d 41 f9 81 f6 ff d0 82 f6 ff d0 83 f6 ff d0 13 c1 04 91 21 70 24 91 42 f0 15 91 63 f8 1b 91 e0 03 13 aa}  //weight: 1, accuracy: High
        $x_1_2 = {a8 00 00 d0 08 [0-4] f9 c1 f5 ff d0 c2 f5 ff d0 c3 f5 ff d0 13 c1 04 91 21 30 1f 91 42 70 32 91 63 1c 0f 91 e0 03 13 aa}  //weight: 1, accuracy: Low
        $x_1_3 = "_Unwind_GetTextRelBase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Harly_K_2147838105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Harly.K"
        threat_id = "2147838105"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Harly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/uner/sparrow/voice" ascii //weight: 1
        $x_1_2 = "deleting file and creating new directory" ascii //weight: 1
        $x_1_3 = "qulcnd5BAOc2NixUFmrPgx+DAD1V/hpoK4nowHOBbg=" ascii //weight: 1
        $x_1_4 = "reward_video=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


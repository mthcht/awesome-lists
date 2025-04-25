rule Trojan_AndroidOS_SoumniBot_C_2147915766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SoumniBot.C"
        threat_id = "2147915766"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SoumniBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "softwareapp/BootBroadcastReceiver" ascii //weight: 2
        $x_2_2 = "d3NzOi8vd3d3Lm1ha2U2OS5pbmZvOjg3NjU=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SoumniBot_G_2147940017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SoumniBot.G!MTB"
        threat_id = "2147940017"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SoumniBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 00 9a ea ff ff 14 01 cb 47 00 00 90 00 00 01 94 00 00 01 3c 00 1a 00 14 00 1c 22 00 00 14 01 9f 03 00 00 91 01 00 01 90 01 00 01 94 00 01 01 2a 00 07 00 00 00 91 01 00 01 94 00 01 01 94 00 01 01 2a 00 f7 ff ff ff 2a 00 25 00 00 00 14 05 b6 ff 60 41 14 04 00 00 00 00 39 04 06 00 14 06 ad ff 60 41 28 0b 22 02 6b 00 1b 07 28 02 00 00 71 10 c9 00 07 00 0c 07 28 ee b7 65 38 04 0a 00 1b 07 77 02 00 00 71 10 c9 00 07 00}  //weight: 1, accuracy: High
        $x_1_2 = {14 03 d2 1d 08 00 71 40 92 00 33 33 0a 03 14 04 a7 55 0d 00 71 10 71 00 04 00 0a 04 01 35 35 34 2c 00 62 05 11 00 35 43 07 00 6e 20 f6 00 45 00 d8 05 04 01 1b 04 40 02 00 00 71 10 c9 00 04 00 0c 04 1b 05 94 03 00 00 71 10 c9 00 05 00 0c 05 22 05 c9 00 12 04 01 45 12 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MacOS_Nukespd_B_2147766863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Nukespd.B!MTB"
        threat_id = "2147766863"
        type = "Trojan"
        platform = "MacOS: "
        family = "Nukespd"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sche-eg.org/plugins/top.php" ascii //weight: 2
        $x_4_2 = {41 b9 e8 03 00 00 41 f7 f9 48 8b bd 58 ff ff ff 4c 8b 85 60 ff ff ff 89 95 28 ff ff ff 4c 89 c2 4c 8d 1d 51 4b 00 00 48 89 8d 20 ff ff ff 4c 89 d9 4c 8b 85 68 ff ff ff 44 8b 8d 54 ff ff ff 44 8b 95 50 ff ff ff 44 89 14 24 44 8b 95 4c ff ff ff 44 89 54 24 08 44 8b 95 34 ff ff ff 44 89 54 24 10 4c 8b 9d 38 ff ff ff 4c 89 5c 24 18}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


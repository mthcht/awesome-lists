rule Trojan_Win64_Bokbot_DA_2147808800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bokbot.DA!MTB"
        threat_id = "2147808800"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bokbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 24 40 8a 4c 24 48 0b c8 88 4c 24 40 8a 44 24 48 02 c0 88 44 24 48 8a 44 24 50 fe c8 88 44 24 50 8a 44 24 50 84 c0 75 ?? 0f b6 44 24 40 8a 4c 24 58 33 c8 88 4c 24 40 8a 44 24 58 fe c0 88 44 24 58 8a 44 24 40 41 88 00 49 ff c0 83 c3 ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


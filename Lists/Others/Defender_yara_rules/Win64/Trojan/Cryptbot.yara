rule Trojan_Win64_Cryptbot_JT_2147927771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cryptbot.JT!MTB"
        threat_id = "2147927771"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 ca 48 8b c7 41 ff c2 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 17 48 2b c8 49 0f af cf 8a 44 0d a7 43 32 04 19 41 88 03 49 ff c3 41 81 fa 00 ba 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


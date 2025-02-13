rule Trojan_Win32_Torbot_RPY_2147850590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Torbot.RPY!MTB"
        threat_id = "2147850590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Torbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 33 c9 33 db 33 d2 8b 45 08 8a 10 80 ca 60 03 da d1 e3 03 45 10 8a 08 84 c9 e0 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


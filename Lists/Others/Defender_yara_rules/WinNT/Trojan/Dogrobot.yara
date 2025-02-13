rule Trojan_WinNT_Dogrobot_F_2147626544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Dogrobot.F"
        threat_id = "2147626544"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 8b 50 3c 8b 41 10 8b 08 a1 ?? ?? ?? ?? 39 48 08 76 1f 8b 30 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 02 89 04 8e 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 8b 4d 0c 8b 71 18 83 61 1c 00 32 d2 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Dogrobot_G_2147627778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Dogrobot.G"
        threat_id = "2147627778"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 e4 10 00 00 c0 8b 4d 0c 8b 41 60 8b 50 0c 89 55 e0 8b 49 0c 89 4d dc 8b 40 04 89 45 d8 60 f5 61 81 7d e0 04 20 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule PWS_Win64_Zbot_A_2147684735_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Zbot.A"
        threat_id = "2147684735"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Zbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 39 2d 75 ?? 0f b7 41 02 83 f8 66 74 ?? 83 f8 69 74}  //weight: 1, accuracy: Low
        $x_1_2 = {42 8a 04 09 43 88 04 08 42 88 14 09 43 0f b6 0c 08 03 ca 0f b6 c1 42 8a 0c 08 30 0b 48 ff c3 48 ff cf 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win64_Zbot_A_2147694389_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Zbot.gen!A"
        threat_id = "2147694389"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 64 86 00 00 66 39 43 04 0f 85 b6 00 00 00 0f b7 43 14 41 b9 04 00 00 00 41 b8 00 10 00 00 48 8d 6c 18 18 0f b7 43 06 48 8d 0c 80}  //weight: 1, accuracy: High
        $x_1_2 = {48 63 4a 3c 48 03 ca 8b 01 41 33 c1 3d ?? ?? ?? ?? 0f 85 ?? 00 00 00 b8 4c 01 00 00 66 39 41 04 75 5a b8 0b 01 00 00 66 39 41 18}  //weight: 1, accuracy: Low
        $x_1_3 = "\"%s\" -installer \"%s\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


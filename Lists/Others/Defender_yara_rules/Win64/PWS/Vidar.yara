rule PWS_Win64_Vidar_STA_2147956267_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Vidar.STA"
        threat_id = "2147956267"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d5 78 e9 26 05 d8 24 06 01 c1 c8 03 3d 37 89 41 00 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 0f 42 c1 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c1 c1 e1 0d 31 c1 89 c8 c1 e8 11 31 c8 89}  //weight: 1, accuracy: High
        $x_1_3 = {48 69 c0 80 96 98 00 ?? ?? 00 80 3e d5 de b1 9d 01}  //weight: 1, accuracy: Low
        $x_1_4 = {48 ff c0 48 3d a0 86 01 00 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 0f 42 c1 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {6c 31 41 a3 b8}  //weight: 1, accuracy: High
        $x_1_6 = {43 3a 5c 00 c7 44 24 ?? 00 00 00 00 48 8d [0-6] ba 04 01 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_2_7 = "[%04d-%02d-%02d %02d:%02d:%02d.%03d | +%lu.%03lus]" ascii //weight: 2
        $x_1_8 = "%08lX%04lX%08lX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win64_Vidar_CH_2147957248_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Vidar.CH!MTB"
        threat_id = "2147957248"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://telegram.me/" ascii //weight: 2
        $x_2_2 = "Browser List" ascii //weight: 2
        $x_2_3 = "Chromium Plugins" ascii //weight: 2
        $x_2_4 = "Firefox Plugins" ascii //weight: 2
        $x_2_5 = "Wallet Rules" ascii //weight: 2
        $x_2_6 = "File Grabber Rules" ascii //weight: 2
        $x_2_7 = "Loader Tasks" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


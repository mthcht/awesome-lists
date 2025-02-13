rule Trojan_Win32_Truebot_A_2147724321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Truebot.A"
        threat_id = "2147724321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Truebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 6a 4c ff d6 8b d8 6a 4d 89 5d d4 ff d6 6a 4e 89 45 e8 ff d6 8b f8 6a 4f 89 7d d0 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = "\\\\.\\pipe\\{73F7975A-A4A2-4AB6-9121-AECAE68AABBB}" ascii //weight: 1
        $x_1_3 = "\\ScreenMonitorService\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Truebot_A_2147724321_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Truebot.A"
        threat_id = "2147724321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Truebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 9b 00 00 00 00 8d 88 ?? ?? ?? ?? 03 ce 81 f9 cc b8 00 00 73 72 8a 88 ?? ?? ?? ?? 30 8c 10 ?? ?? ?? ?? 8d 4a 01 03 c8 81 f9 cc b8 00 00 73 57 8a 88 ?? ?? ?? ?? 30 8c 10 ?? ?? ?? ?? 8d 4a 02 03 c8 81 f9 cc b8 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 6d 73 73 2e 74 78 74 [0-16] 5c 6d 73 73 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "\\\\.\\pipe\\{73F7975A-A4A2-4AB6-9121-AECAE68AABBB}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Truebot_SB_2147846357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Truebot.SB"
        threat_id = "2147846357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Truebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 [0-255] 2c 00 43 00 68 00 6b 00 64 00 73 00 6b 00 45 00 78 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


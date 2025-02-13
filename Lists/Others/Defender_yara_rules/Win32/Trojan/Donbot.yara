rule Trojan_Win32_Donbot_A_2147647577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Donbot.A"
        threat_id = "2147647577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Donbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 42 4c 3a 20 25 6c 75 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = "{BASE64EMAIL}" ascii //weight: 1
        $x_1_3 = "{qp_start}" ascii //weight: 1
        $x_1_4 = "Max-Threads: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Donbot_A_2147647577_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Donbot.A"
        threat_id = "2147647577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Donbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "email=%s" ascii //weight: 1
        $x_1_2 = "POST /gateway/index HTTP/1.0" ascii //weight: 1
        $x_1_3 = {8b 44 24 10 30 0c 06 57 43 e8 ?? ?? ?? ?? 59 3b d8 72 e7 8b 44 24 10 f6 14 06 50 46 e8 ?? ?? ?? ?? 59 3b f0 72 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


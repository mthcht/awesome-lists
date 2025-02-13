rule Trojan_Win32_TeleBot_SB_2147899921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TeleBot.SB!MTB"
        threat_id = "2147899921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TeleBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 38 8b 44 24 ?? 30 14 06 8b 6c 24 ?? 8b 5c 24 ?? 83 c6 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cd 2b cb b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 3b f0 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


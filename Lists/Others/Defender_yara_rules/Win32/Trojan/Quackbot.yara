rule Trojan_Win32_Quackbot_2147731357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quackbot"
        threat_id = "2147731357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quackbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 d4 8a 14 3a 22 55 ?? 88 10 8b 55 ?? 47 3b 55 ?? eb ?? d3 f8 8b 4d ?? 29 c1 89 f0 99 f7 7d ?? 0f af c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_BattDual_RPY_2147896369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BattDual.RPY!MTB"
        threat_id = "2147896369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BattDual"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 2b 4d e4 89 4d e0 8b 55 e0 83 c2 01 89 55 f0 6a 04 68 00 10 00 00 8b 45 f0 50 6a 00 8b 4d f4 51 ff 15 ?? ?? ?? ?? 89 45 e8 6a 00 8b 55 f0 52 8b 45 ec 50 8b 4d e8 51 8b 55 f4 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


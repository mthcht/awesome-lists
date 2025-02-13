rule Trojan_Win32_Dbot_DEA_2147761739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dbot.DEA!MTB"
        threat_id = "2147761739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 03 f0 d3 e2 89 b5 ?? fd ff ff 8b f0 c1 ee 05 03 95 ?? fd ff ff 03 b5 ?? fd ff ff 89 55 f8 8b 85 ?? fd ff ff 31 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


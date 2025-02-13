rule Trojan_Win32_Trikbot_AA_2147799276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trikbot.AA!MTB"
        threat_id = "2147799276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trikbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b 01 51 8b 0a 33 c1 59 52 8b d0 51 03 cf 51 58 89 10 59 5a 58 42 42 42 42 3b 55 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


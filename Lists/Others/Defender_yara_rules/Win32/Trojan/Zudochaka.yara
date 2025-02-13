rule Trojan_Win32_Zudochaka_RPX_2147843607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zudochaka.RPX!MTB"
        threat_id = "2147843607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zudochaka"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 8b 45 e4 8b 10 ff 12 03 45 c4 50 6a 00 ff 55 a4 89 45 e0 8b 45 ac 2d 5f 0a 00 00 50 8b 45 b0 2d e3 04 00 00 50 8b 45 e4 8b 10 ff 12 03 45 c4 50}  //weight: 1, accuracy: High
        $x_1_2 = {2b d8 8b 45 d8 31 18 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 72 b1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


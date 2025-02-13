rule Trojan_Win32_Krazy_CCJK_2147918933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krazy.CCJK!MTB"
        threat_id = "2147918933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 b8 b4 65 00 68 68 61 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 30 b2 65 00 33 d2 8a d4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Mispadu_PA_2147745193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mispadu.PA!MTB"
        threat_id = "2147745193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mispadu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f0 8b 55 f4 8a 12 80 ea 41 8d 14 92 8d 14 92 8b 4d f4 8a 49 01 80 e9 41 02 d1 8b ce 2a d1 8b cf 2a d1 e8 ?? ?? ?? ?? 8b 55 f0 8b c3 e8 ?? ?? ?? ?? 8d 45 f4 50 8b 45 f4 e8 ?? ?? ?? ?? 8b c8 ba 03 00 00 00 8b 45 f4 e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 85 c0 7f a6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


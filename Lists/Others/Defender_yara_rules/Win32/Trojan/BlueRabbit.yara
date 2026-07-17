rule Trojan_Win32_BlueRabbit_GVA_2147973636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlueRabbit.GVA!MTB"
        threat_id = "2147973636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlueRabbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 94 24 a0 00 00 00 89 d6 c1 ea 08 89 54 24 64 89 d7 83 f2 27 0f b6 d2 44 8b 84 24 a4 00 00 00 4c 8b 8c 24 a8 00 00 00 4c 8b 94 24 98 00 00 00 b9 0e 00 00 00 31 db 41 bb 27 00 00 00 45 31 e4 eb 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


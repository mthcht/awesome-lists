rule Trojan_Win32_Agentesla_2147748036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agentesla!MTB"
        threat_id = "2147748036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agentesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 37 32 da 32 d8 32 d9 88 1e 8a d8 32 d9 22 da 8b 55 14 8d 3c d5 00 00 00 00 33 fa 81 e7 ?? ?? 00 00 c1 e7 14 c1 ea 08 0b d7 8d 3c 00 33 f8 22 c8 c1 e7 04 33 f8 32 cb 8b d8 83 e7 ?? c1 e3 07 33 fb c1 e7 ?? c1 e8 08 0b c7 46 ff 4d 10 89 55 14 75 a9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


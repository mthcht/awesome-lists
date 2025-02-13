rule Trojan_Win32_Ardamax_DB_2147816549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ardamax.DB!MTB"
        threat_id = "2147816549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 1c 8a 1c 3e 8b c6 83 e0 7f 8a 14 08 8b c6 32 d3 83 e0 07 b9 08 00 00 00 8a da 2b c8 d2 e3 8a c8 d2 ea 0a da 88 1c 3e 46 3b f5 72 d1}  //weight: 2, accuracy: High
        $x_2_2 = "C:\\file.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


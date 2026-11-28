rule Trojan_Win32_CryptMiner_CG_2147982949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptMiner.CG!MTB"
        threat_id = "2147982949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 02 00 00 00 c9 0f 21 00 00 00 00 00 36 21 0f 00 00 00 00 00 00 4a 42 00 16 95 10 4e be c3 0e}  //weight: 5, accuracy: High
        $x_2_2 = "VerySilent" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


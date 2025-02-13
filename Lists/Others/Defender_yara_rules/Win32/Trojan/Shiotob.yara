rule Trojan_Win32_Shiotob_RPY_2147845545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shiotob.RPY!MTB"
        threat_id = "2147845545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shiotob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b c2 99 2b c1 8b c8 0f b7 dd 1b d7 8d 04 8d 00 00 00 00 8b fa 2b d8 8b 54 24 10 0f b7 c5 89 32 33 ed 99 8b f3 2b f0 1b ea 2b f1 1b ef 83 44 24 10 04 83 6c 24 14 01 8b ce 8b fd 0f 85 7a ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


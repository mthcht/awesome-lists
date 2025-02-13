rule Trojan_Win32_SquirrelWaffel_A_2147794791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SquirrelWaffel.A!MTB"
        threat_id = "2147794791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SquirrelWaffel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf 6b c9 33 2b ca 2b ca 8d 5c 39 ?? 2a c2 b1 53 f6 e9 8a ca 02 c9 02 c1 02 c3 2c 01 b1 53 f6 e9 8a ca 2a c8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 c8 6b c9 53 56 8b 35 ?? ?? ?? ?? 2b f1 8d 4c 32 ?? 66 0f b6 d0 66 03 d6 66 83 ea 5c 0f b7 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


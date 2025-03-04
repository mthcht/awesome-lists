rule Trojan_Win32_ZenPack_FXB_2147817733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZenPack.FXB!MTB"
        threat_id = "2147817733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZenPack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f be d1 80 e9 41 8b c2 83 c8 20 80 f9 19 8a 0b 0f 47 c2 33 c6 69 f0 a1 01 00 01 43 84 c9 75 e0}  //weight: 10, accuracy: High
        $x_1_2 = "LoadLibraryC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


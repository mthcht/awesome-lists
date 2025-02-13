rule Trojan_Win32_PbrabLoader_A_2147903171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PbrabLoader.A!MTB"
        threat_id = "2147903171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PbrabLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 04 50 6b c0 ?? 0f b7 d7 66 2b c2 ba ?? ?? ?? ?? 66 2b 45 ?? 66 03 46 ?? 8b 75 ?? 66 2b c2 8b 55 ?? 83 c6 ?? 89 75 ?? 66 89 04 51 42 8b 7d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


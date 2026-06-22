rule Trojan_Win32_ElephantRAT_MKV_2147972066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ElephantRAT.MKV!MTB"
        threat_id = "2147972066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ElephantRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 c7 45 e0 ?? 97 cb f9 c7 45 e4 a5 b6 84 9f c6 45 e8 00 c7 45 d0 a1 b2 c3 d4 c7 45 d4 e5 f6 a7 b8 c7 45 d8 ?? ?? ?? ?? 8a 44 0d d0 30 44 0d dc 41 83 f9 0c 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


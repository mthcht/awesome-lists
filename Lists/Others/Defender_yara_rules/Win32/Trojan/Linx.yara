rule Trojan_Win32_Linx_HA_2147941923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Linx.HA!MTB"
        threat_id = "2147941923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Linx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 72 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 [0-48] 2e 00 64 00 61 00 74 00 2c 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


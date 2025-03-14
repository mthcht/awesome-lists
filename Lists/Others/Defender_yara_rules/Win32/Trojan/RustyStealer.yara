rule Trojan_Win32_RustyStealer_ME_2147907648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RustyStealer.ME!MTB"
        threat_id = "2147907648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 fc 19 00 00 00 8b c3 0f b6 0e f7 75 fc 41 0f af cb 8a 44 15 d8 30 81 77 af 00 10 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


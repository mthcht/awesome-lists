rule Trojan_Win32_Danglo_A_2147647903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danglo.A"
        threat_id = "2147647903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danglo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ba 01 00 00 00 89 e5 31 c0 83 ec 18 b9 ?? ?? ?? ?? 89 54 24 14 ba ?? ?? ?? ?? 89 44 24 10 b8 ?? ?? ?? ?? 89 4c 24 0c 89 54 24 08 89 44 24 04 c7 04 24 00 00 00 00 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {b9 01 00 00 00 89 44 24 08 89 4c 24 04 89 34 24 e8 ?? ?? ?? ?? 89 74 24 04 8d 95 64 ff ff ff b8 ?? ?? ?? ?? 89 54 24 0c 89 44 24 08 89 3c 24 e8 ?? ?? ?? ?? 83 ec 10 85 c0 75 ?? 89 1c 24 e8}  //weight: 2, accuracy: Low
        $x_1_3 = "Accept: */*" ascii //weight: 1
        $x_1_4 = "LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


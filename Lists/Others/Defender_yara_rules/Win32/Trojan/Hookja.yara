rule Trojan_Win32_Hookja_A_2147605973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hookja.A"
        threat_id = "2147605973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hookja"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 64 52 ff 15 ?? ?? ?? ?? a1 ?? ?? 00 0e b9 ?? ?? 00 0e c6 00 e9 a1 ?? ?? 00 0e 2b c8 83 e9 05 89 48 01 8b 15 ?? ?? 00 0e 66 c7 42 05 90 90}  //weight: 3, accuracy: Low
        $x_2_2 = {83 fa 04 0f 8e ?? 00 00 00 83 fa 0f 0f 8d ?? 00 00 00 b9 07 00 00 00 33 c0 8d 7d bc 83 c2 fc f3 ab}  //weight: 2, accuracy: Low
        $x_1_3 = "AppInit_DLLs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Ralminey_A_2147694856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ralminey.A"
        threat_id = "2147694856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ralminey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 51 ff 75 ?? 33 c0 c7 45 ?? 31 71 32 77 c7 45 ?? 33 65 34 72 8d 7d ?? 8d 4d ?? aa e8}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fb 94 01 00 00 74 39 81 fb c8 00 00 00 75 31}  //weight: 1, accuracy: High
        $x_1_3 = "aAB0AHQAcAA6AC8ALw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


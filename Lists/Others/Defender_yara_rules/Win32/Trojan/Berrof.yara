rule Trojan_Win32_Berrof_A_2147696372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Berrof.A"
        threat_id = "2147696372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Berrof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 18 89 f1 89 c6 89 fa f3 a4 c7 00 77 77 77 77 81 c2 ?? ?? 00 00 6a 02 ff d2 6a 00 ff 93}  //weight: 1, accuracy: Low
        $x_1_2 = {81 3e 03 01 00 00 74 08 81 3e 00 01 00 00 75 0a 81 3f 77 77 77 77}  //weight: 1, accuracy: High
        $x_1_3 = {76 65 72 63 6c 73 69 64 00 50 ff 93 ?? ?? ?? ?? 85 c0 0f 84 a3 00 00 00 c7 85 dc fc ff ff 07 00 01 00 8d 95 dc fc ff ff 52 ff 75 f0 ff 93}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


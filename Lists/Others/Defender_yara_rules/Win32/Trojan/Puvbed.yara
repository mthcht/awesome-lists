rule Trojan_Win32_Puvbed_A_2147601194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Puvbed.A"
        threat_id = "2147601194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Puvbed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 d3 8b 4c 24 18 51 8b c2 25 ff 00 00 00 50 8b 44 24 18 0f b6 ce 51 c1 e8 10 0f b6 c0 50 c1 ea 18 52 68 ?? ?? 40 00 8d 4c 24 ?? 68 80 00 00 00}  //weight: 3, accuracy: Low
        $x_3_2 = {75 f4 8b bc 24 ?? 00 00 00 8b 2d ?? ?? 40 00 8d 64 24 00 e8 ?? ?? 00 00 99 f7 fe 57 8b 14 95 ?? ?? 40 00 8b c2 25 ff 00 00 00 50 8b c2 0f b6 ce 51 c1 e8 10 0f b6 c0 50 89 54 24 ?? c1 ea 18 52 68 ?? ?? 40 00 8d 4c 24 ?? 68 80 00 00 00}  //weight: 3, accuracy: Low
        $x_1_3 = "c=%d&p=%d&u=%d&v=%d&b=%d&d=%d&g=%s&e=%s" ascii //weight: 1
        $x_1_4 = {2f 78 2e 63 67 69 3f 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 69 6e 74 65 6c 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}


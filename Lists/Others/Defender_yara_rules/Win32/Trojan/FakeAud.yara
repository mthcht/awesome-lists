rule Trojan_Win32_FakeAud_A_2147642278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAud.A"
        threat_id = "2147642278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 38 00 74 ?? 80 78 01 00 74 ?? 80 78 02 00 74 ?? 80 78 03 00 75}  //weight: 2, accuracy: Low
        $x_1_2 = {eb 0b 61 75 78 4d 65 73 73 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {eb 0b 6d 6f 64 4d 65 73 73 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\System\\npdrmv2.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


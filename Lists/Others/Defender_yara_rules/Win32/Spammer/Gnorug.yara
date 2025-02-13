rule Spammer_Win32_Gnorug_A_2147599361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Gnorug.A"
        threat_id = "2147599361"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Gnorug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 f9 77 69 6e 6c 0f 85 cb 00 00 00 8b 4e 04 0b c8 81 f9 6f 67 6f 6e 0f 85 ba 00 00 00 8b 4e 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


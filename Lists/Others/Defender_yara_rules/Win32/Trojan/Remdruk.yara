rule Trojan_Win32_Remdruk_A_2147640686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remdruk.A"
        threat_id = "2147640686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remdruk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 56 8b 74 24 14 8a 1c 07 30 1c 31 40 3b c5 72 02 33 c0 41 3b ca 72 ee 5e 5b 5f 5d c3}  //weight: 2, accuracy: High
        $x_1_2 = "1dM3uu4j7Fw4sjnbcwlDqet4F7Jyu" ascii //weight: 1
        $x_1_3 = "with MS05-010+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Saiterec_A_2147624438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Saiterec.A"
        threat_id = "2147624438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Saiterec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {69 6e 63 72 61 74 65 73 2e 63 6f 6d 2f 6c 6f 67 2e 70 68 70 00}  //weight: 3, accuracy: High
        $x_2_2 = {69 4d 6f 64 75 6c 65 2e 64 6c 6c 00 66 00 69 00 6f 00 73 00}  //weight: 2, accuracy: High
        $x_2_3 = {26 61 66 66 69 64 3d 00 53 6f 66 74 77 61 72 65}  //weight: 2, accuracy: High
        $x_1_4 = "%s?sid=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


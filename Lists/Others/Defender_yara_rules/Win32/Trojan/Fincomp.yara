rule Trojan_Win32_Fincomp_B_2147696923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fincomp.B"
        threat_id = "2147696923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fincomp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 63 20 6e 65 74 20 73 74 6f 70 20 54 65 72 6d 53 65 72 76 69 63 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "MyPin|" ascii //weight: 1
        $x_1_3 = "%s\\in.temp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


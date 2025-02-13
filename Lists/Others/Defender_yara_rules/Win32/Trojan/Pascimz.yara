rule Trojan_Win32_Pascimz_A_2147624021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pascimz.A"
        threat_id = "2147624021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pascimz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = " Adult PDF Password R" wide //weight: 5
        $x_5_2 = {75 00 6d 00 62 00 65 00 72 00 20 00 3a 00 00 00 00 00 00 00 00 08 80 50 00 00 00 00 0e 00 2f 00}  //weight: 5, accuracy: High
        $x_1_3 = "http://www.cim.zor.org" ascii //weight: 1
        $x_1_4 = {00 1c 1c 18 52 47 47 1f 1f 1f 46 0b 01 05 46 12 07 1a 46 07 1a 0f 47 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


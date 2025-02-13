rule Trojan_Win32_TibsEnum_A_2147594598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TibsEnum.A"
        threat_id = "2147594598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TibsEnum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 64 6f 74 5d 20 00 20 64 6f 67 20 00 00 00 20 3c 61 74 3e 20 00 00 2d 61 74 2d}  //weight: 1, accuracy: High
        $x_1_2 = {7b 61 74 7d 20 00 00 5b 61 2e 74 2e 5d 00 00 28}  //weight: 1, accuracy: High
        $x_1_3 = {74 09 c7 45 0c 6b 6f 00 00 eb}  //weight: 1, accuracy: High
        $x_1_4 = {46 83 fe 05 7e de 3d 74 73 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {81 bd 9c fb ff ff 66 74 70 3a 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


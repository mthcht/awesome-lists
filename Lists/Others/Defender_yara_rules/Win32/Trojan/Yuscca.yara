rule Trojan_Win32_Yuscca_A_2147685328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yuscca.A"
        threat_id = "2147685328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yuscca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChewBacca" ascii //weight: 1
        $x_1_2 = {75 6d 65 6d 73 63 61 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 73 67 73 63 61 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 65 63 76 64 61 74 61 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = "[0-9]{13,19}=[0-9]{5,50}\\?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


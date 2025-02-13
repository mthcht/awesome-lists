rule Trojan_Win32_Doshye_A_2147603007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doshye.A"
        threat_id = "2147603007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doshye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 44 62 69 6e 21 4e 67 67 0c 0b 73 64 66 64 65 68 75 21 2e 72 21 24 56 48 4f 45 48 53 24 5d 72 78 72 75 64 6c 5d 72 77 62 69 64 72 75 2f 73 64 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


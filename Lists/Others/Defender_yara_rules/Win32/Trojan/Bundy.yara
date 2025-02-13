rule Trojan_Win32_Bundy_C_2147638674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bundy.C"
        threat_id = "2147638674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bundy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 70 65 6e 00 74 61 73 6b 6b 69 6c 6c 00 2f 66 20 2f 69 6d 20 4b 53 57 65 62 53 68 69 65 6c 64 2e 65 78 65 00 6f 70 65 6e 20 74 61 73 6b 6b 69 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {5c 6b 69 6e 67 73 6f 66 74 00 73 70 69 74 65 73 70 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_3 = "\\Internat Explorar" ascii //weight: 1
        $x_1_4 = "if exist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


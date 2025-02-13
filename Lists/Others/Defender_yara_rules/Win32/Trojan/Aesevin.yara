rule Trojan_Win32_Aesevin_B_2147628643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aesevin.B"
        threat_id = "2147628643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aesevin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 61 37 2e 69 6e 69 00 30 00 6e 00 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {47 30 30 47 4c 45 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 6f 64 79 00 69 6e 6e 65 72 48 54 4d 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


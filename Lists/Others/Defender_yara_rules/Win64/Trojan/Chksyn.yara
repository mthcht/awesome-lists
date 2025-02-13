rule Trojan_Win64_Chksyn_A_2147717858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Chksyn.A"
        threat_id = "2147717858"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Chksyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 01 48 8d 14 24 41 b9 0d 00 00 00 32 02 48 ff c2 49 83 e9 01 75 f5 88 01 48 ff c1 49 83 e8 01 75 de}  //weight: 1, accuracy: High
        $x_1_2 = {6e 65 74 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 [0-8] 6e 65 74 20 73 74 6f 70 20 4d 70 73 53 76 63}  //weight: 1, accuracy: Low
        $x_1_3 = "v=%d&s=%d&h=%d&un=%s&o=%d&c=%d&ip=%s&sys=%s&uid=%d&w=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


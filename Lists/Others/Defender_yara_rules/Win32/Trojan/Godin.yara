rule Trojan_Win32_Godin_A_2147678728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Godin.A"
        threat_id = "2147678728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Godin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" ascii //weight: 1
        $x_1_2 = {49 50 48 4f 4e 45 38 2e 35 28 68 6f 73 74 3a 25 73 2c 69 70 3a 25 73 29 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 46 58 53 53 54 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_4 = "a dingo's got my baby" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


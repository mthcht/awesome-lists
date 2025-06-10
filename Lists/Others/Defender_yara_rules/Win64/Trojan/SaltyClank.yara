rule Trojan_Win64_SaltyClank_A_2147943292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SaltyClank.A"
        threat_id = "2147943292"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SaltyClank"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 6f 75 6c 64 6e 27 74 20 65 78 74 72 61 63 74 20 6b 65 79 20 2d 20 63 6f 72 72 75 70 74 65 64 20 66 69 6c 65 3f 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 76 61 6c 69 64 20 61 72 67 75 6d 65 6e 74 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = "cmd.exe /e:ON /v:OFF /d /c" ascii //weight: 1
        $x_1_4 = "C:\\Users\\lucak\\.cargo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


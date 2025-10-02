rule Trojan_Win64_VaporDolphin_A_2147953816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VaporDolphin.A"
        threat_id = "2147953816"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VaporDolphin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 25 73 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 50 6f 77 65 72 53 68 65 6c 6c 0d 0a 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 63 6c 6f 73 65 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = "msiexec.exe /i " wide //weight: 1
        $x_1_3 = "powershell -enc \"%hs\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Boupke_A_2147605816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boupke.gen!A"
        threat_id = "2147605816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boupke"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 45 08 8b 75 0c 68 e8 03 00 00 68 c8 08 00 00 8d 54 24 10 52 68 00 08 00 00 68 ?? ?? 00 10 b9 ac 01 00 00 8d bc 24 34 02 00 00}  //weight: 4, accuracy: Low
        $x_1_2 = {4b 00 65 00 72 00 6e 00 65 00 6c 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 00 73 00 53 00 79 00 6e 00 46 00 6c 00 6f 00 6f 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 63 00 72 00 69 00 70 00 74 00 46 00 6c 00 6f 00 6f 00 64 00 55 00 72 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {4b 00 65 00 72 00 6e 00 65 00 6c 00 43 00 68 00 65 00 63 00 6b 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "\\KernelBot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}


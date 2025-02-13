rule Trojan_Win32_Radyoork_A_2147685508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radyoork.A"
        threat_id = "2147685508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radyoork"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ypool.net:8080 -u Darky101.1 -p pineapple -m512" wide //weight: 10
        $x_4_2 = "Protominer.exe -o http://ypool" wide //weight: 4
        $x_2_3 = "rentVersion\\Run\\ /f /v Load /t REG_SZ /d" wide //weight: 2
        $x_1_4 = {83 e2 03 03 c2 c1 f8 02 83 e8 01 0f 80 be 02 00 00 33 f6 89 45 98 89 75 dc 3b f0 0f 8f 44 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


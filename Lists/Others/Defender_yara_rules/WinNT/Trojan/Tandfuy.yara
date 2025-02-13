rule Trojan_WinNT_Tandfuy_A_2147684329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Tandfuy.A"
        threat_id = "2147684329"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Tandfuy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 41 00 68 00 6e 00 46 00 6c 00 74 00 32 00 4b 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 6d 00 73 00 73 00 65 00 63 00 65 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8d 75 ?? a5 a4 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Tandfuy_B_2147684330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Tandfuy.B"
        threat_id = "2147684330"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Tandfuy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 41 00 68 00 6e 00 46 00 6c 00 74 00 32 00 4b 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 06 4d c6 46 01 5a c6 46 02 90 88 5e 03 c6 46 04 03 88 5e 05 88 5e 06 88 5e 07 c6 46 08 04 88 5e 09 ff 15 ?? ?? ?? ?? 53 53 6a 20 6a 03 6a 02 6a 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Belanit_A_2147652426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Belanit.A"
        threat_id = "2147652426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Belanit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Mozilla/5.0 (compatiblep; MSIE " ascii //weight: 1
        $x_1_2 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 65 74 2d 63 6f 6f 6b 69 65 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = "&start=" wide //weight: 1
        $x_1_5 = "onmousedown" wide //weight: 1
        $x_1_6 = {8b f0 85 f6 0f 84 90 00 00 00 6a 00 68 00 00 00 80 6a 00 6a 00 8b c7 e8 ?? ?? ?? ff 50 56 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Belanit_C_2147652510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Belanit.C"
        threat_id = "2147652510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Belanit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AppHook" ascii //weight: 1
        $x_1_2 = "MouseHook" ascii //weight: 1
        $x_1_3 = "sniff" ascii //weight: 1
        $x_1_4 = "silent" ascii //weight: 1
        $x_1_5 = {7e 53 79 73 74 65 6d 43 61 63 68 65 2e 62 61 74 00 00 00 00 53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 00}  //weight: 1, accuracy: High
        $x_10_6 = {33 d2 33 c9 8a 50 02 33 db 8a 48 01 8a 18 89 5d f4 83 c0 03 8b 1c 96 8b 7d f4 03 9c 8e 00 04 00 00 03 9c be 00 08 00 00 8b 7d e8 c1 fb 10}  //weight: 10, accuracy: High
        $x_10_7 = {8b f0 85 f6 0f 84 90 00 00 00 6a 00 68 00 00 00 80 6a 00 6a 00 8b c7 e8 ?? ?? ?? ff 50 56 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


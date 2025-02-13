rule Worm_Win32_Bancorkut_B_2147603565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bancorkut.B"
        threat_id = "2147603565"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancorkut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 8d 55 d0 33 c9}  //weight: 2, accuracy: High
        $x_1_2 = {ff 6a 00 68 ?? ?? ?? 00 6a 00 56 e8 ?? ?? ?? ff 8b f8 6a 00 68 ?? ?? ?? 00 6a 00 57 e8 ?? ?? ?? ff 8b f8 6a 00 68 ?? ?? ?? 00 6a 00 57 e8 ?? ?? ?? ff 8b f8 6a 03 56 e8 ?? ?? ?? ff 8b c3 e8 00 0a 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72}  //weight: 1, accuracy: Low
        $x_2_3 = {2a 2e 64 62 78 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 3a 5c [0-60] 64 62 78 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2a 2e 77 61 62 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 77 61 62 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2a 2e 6d 62 78 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6d 62 78 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2a 2e 65 6d 6c}  //weight: 2, accuracy: Low
        $x_1_4 = "www.orkut.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Bancorkut_C_2147619196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bancorkut.C"
        threat_id = "2147619196"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancorkut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 61 63 63 6f 75 6e 74 73 2f 73 65 72 76 69 63 65 6c 6f 67 69 6e 3f 63 6f 6e 74 69 6e 75 65 00 00 00 ff ff ff ff 21 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 6f 72 6b 75 74 2e 63 6f 6d 2e 62 72 2f 48 6f 6d 65 2e 61 73 70 78}  //weight: 10, accuracy: High
        $x_10_2 = "www.google.com/accounts/servicelogin?service=orkut" ascii //weight: 10
        $x_10_3 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 00 00 00 00 ff ff ff ff 1b 00 00 00 50 61 67 69 6e 61 20 64 6f 20 6f 72 6b 75 74 20 66 6f 69 20 61 62 65 72 74 61 21}  //weight: 10, accuracy: High
        $x_5_4 = "Embedded Web Browser from: http://bsalsa.com/" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}


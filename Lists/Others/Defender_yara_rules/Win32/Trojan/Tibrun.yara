rule Trojan_Win32_Tibrun_A_2147685833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibrun.A"
        threat_id = "2147685833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/www/cmd.php HTT" ascii //weight: 1
        $x_1_2 = {22 67 6f 6f 64 73 6c 69 73 74 22 20 3a 20 22 00 2c 20 22 70 70 73 22 20 3a}  //weight: 1, accuracy: High
        $x_1_3 = "\"bruting\" : " ascii //weight: 1
        $x_1_4 = {00 31 2e 62 61 74 [0-4] 00 69 70 2e 73 79 73 [0-4] 00 31 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tibrun_A_2147685833_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibrun.A"
        threat_id = "2147685833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {22 62 61 64 22 20 3a 20 00 2c 20 22 62 72 75 74 69 6e 67 22 20 3a}  //weight: 10, accuracy: High
        $x_10_2 = "brut.loc/www" ascii //weight: 10
        $x_10_3 = {b9 19 00 00 00 f3 a4 b8 64 65 6c 20 ab b8 2f 41 3a 53 ab 66 b8 2f 41 66 ab 66 b8 20 22}  //weight: 10, accuracy: High
        $x_1_4 = {b8 41 63 63 65}  //weight: 1, accuracy: High
        $x_1_5 = {b8 70 74 2d 45}  //weight: 1, accuracy: High
        $x_1_6 = {b8 20 67 7a 69}  //weight: 1, accuracy: High
        $x_1_7 = {b8 69 6e 67 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tibrun_B_2147687029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibrun.B"
        threat_id = "2147687029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 50 04 8b 00 8b 40 0c 83 c0 02 89 82 b8 00 00 00 8b 52 18 f6 c6 05 75 21 bf ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 17 33 d0 89 17 83 c7 04 e2 f5 b8 ff ff ff ff c3}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 19 00 00 00 f3 a4 c7 07 64 65 6c 20 83 c7 04 b8 2f 41 3a 53 ab 66 b8 2f 41 66 ab 66 b8 20 22 66 ab 68 04 01 00 00 57}  //weight: 1, accuracy: High
        $x_1_3 = {22 62 61 64 22 20 3a 20 00 2c 20 22 62 72 75 74 69 6e 67 22 20 3a}  //weight: 1, accuracy: High
        $x_1_4 = {50 4f 53 54 [0-16] 2f 77 77 77 2f 63 6d 64 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Tibrun_RPO_2147828101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibrun.RPO!MTB"
        threat_id = "2147828101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibrun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 17 33 d0 89 17 83 c7 04 e2 f5}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 e4 33 c0 8b 00 ff 75 e4}  //weight: 1, accuracy: High
        $x_1_3 = "AddVectoredExceptionHandler" ascii //weight: 1
        $x_1_4 = "RemoveVectoredExceptionHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


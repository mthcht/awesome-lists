rule Trojan_Win64_AutoitInject_ABMB_2147958328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AutoitInject.ABMB!MTB"
        threat_id = "2147958328"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 22 00 69 00 6e 00 74 00 22 00 20 00 2c 00 20 00 22 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 22 00 20 00 2c 00 20 00 22 00 70 00 74 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 22 00 6c 00 6f 00 6e 00 67 00 22 00}  //weight: 4, accuracy: Low
        $x_4_2 = {44 4c 4c 43 41 4c 4c 20 28 20 22 4b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 20 2c 20 22 69 6e 74 22 20 2c 20 22 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 22 20 2c 20 22 70 74 72 22 20 2c 20 24 [0-50] 20 2c 20 22 6c 6f 6e 67 22}  //weight: 4, accuracy: Low
        $x_2_3 = {28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 52 00 49 00 47 00 48 00 54 00 20 00 28 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 34 00 20 00 29 00 20 00 3d 00 20 00 22 00 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {28 20 53 54 52 49 4e 47 52 49 47 48 54 20 28 20 24 [0-50] 20 2c 20 34 20 29 20 3d 20 22 2e 65 78 65 22 20 29}  //weight: 2, accuracy: Low
        $x_4_5 = "& GO ( \"ICAgICAgIERpbSBiIEFzIEJ5dGUoKSA9IENvbnZlcnQuRnJvbUJhc2U2NFN0cmluZyhzcyk=\" ) &" ascii //weight: 4
        $x_4_6 = {26 00 20 00 47 00 4f 00 20 00 28 00 20 00 22 00 49 00 43 00 41 00 67 00 49 00 43 00 41 00 67 00 49 00 43 00 42 00 54 00 4e 00 44 00 41 00 77 00 4c 00 6d 00 6c 00 75 00 61 00 6c 00 4a 00 31 00 62 00 69 00 67 00 69 00 58 00 46 00 64 00 70 00 62 00 6d 00 52 00 76 00 64 00 33 00 4e 00 63 00 54 00 57 00 6c 00 6a 00 63 00 6d 00 39 00 7a 00 62 00 32 00 5a 00 30 00 4c 00 6b 00 35 00 46 00 56 00 46 00 78 00 47 00 63 00 6d 00 46 00 74 00 5a 00 58 00 64 00 76 00 63 00 6d 00 74 00 63 00 64 00 6a 00 51 00 75 00 4d 00 43 00 34 00 7a 00 4d 00 44 00 4d 00 78 00 4f 00 56 00 78 00 [0-100] 22 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_7 = {26 20 47 4f 20 28 20 22 49 43 41 67 49 43 41 67 49 43 42 54 4e 44 41 77 4c 6d 6c 75 61 6c 4a 31 62 69 67 69 58 46 64 70 62 6d 52 76 64 33 4e 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 4c 6b 35 46 56 46 78 47 63 6d 46 74 5a 58 64 76 63 6d 74 63 64 6a 51 75 4d 43 34 7a 4d 44 4d 78 4f 56 78 [0-100] 22 20 29}  //weight: 4, accuracy: Low
        $x_2_8 = {53 00 4c 00 45 00 45 00 50 00 20 00 28 00 20 00 [0-50] 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_9 = {53 4c 45 45 50 20 28 20 [0-50] 20 29}  //weight: 2, accuracy: Low
        $x_2_10 = "GO ( \"QzpcVXNlcnNc\" ) & @USERNAME &" ascii //weight: 2
        $x_4_11 = "GO ( \"XEFwcERhdGFcUm9hbWluZ1xNaWNyb3NvZnRcV2luZG93c1xTdGFydCBNZW51XFByb2dyYW1zXFN0YXJ0dXBcZ29vZ2xlLmV4ZQ==\" )" ascii //weight: 4
        $x_2_12 = {46 00 49 00 4c 00 45 00 43 00 4f 00 50 00 59 00 20 00 28 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 4e 00 41 00 4d 00 45 00 20 00 2c 00 20 00 24 00 [0-50] 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_13 = {46 49 4c 45 43 4f 50 59 20 28 20 40 53 43 52 49 50 54 44 49 52 20 26 20 22 5c 22 20 26 20 40 53 43 52 49 50 54 4e 41 4d 45 20 2c 20 24 [0-50] 20 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 6 of ($x_2_*))) or
            ((4 of ($x_4_*) and 4 of ($x_2_*))) or
            ((5 of ($x_4_*) and 2 of ($x_2_*))) or
            ((6 of ($x_4_*))) or
            (all of ($x*))
        )
}


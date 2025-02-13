rule Trojan_Win32_Derbit_A_2147718306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derbit.A"
        threat_id = "2147718306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derbit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 6a 48 e8 ?? ?? ?? ?? 8d 84 24 ?? ?? ?? ?? 50 6a 49 e8 ?? ?? ?? ?? 8d 84 24 ?? ?? ?? ?? 50 6a 4a e8}  //weight: 3, accuracy: Low
        $x_3_2 = {8a 04 30 32 04 d5 ?? ?? ?? ?? 32 04 d5 ?? ?? ?? ?? 32 c3 43 88 04 3e 0f b7 f3 3b f1 72 db 07 00 8b 04 d5}  //weight: 3, accuracy: Low
        $x_5_3 = {00 70 61 79 6c 6f 61 64 2e 64 6c 6c 00 5f 53 74 61 72 74 40 34 00}  //weight: 5, accuracy: High
        $x_1_4 = "185.121.177.177" ascii //weight: 1
        $x_1_5 = "185.121.177.53" ascii //weight: 1
        $x_1_6 = "45.63.25.55" ascii //weight: 1
        $x_1_7 = "111.67.16.202" ascii //weight: 1
        $x_1_8 = "142.4.204.111" ascii //weight: 1
        $x_1_9 = "142.4.205.47" ascii //weight: 1
        $x_1_10 = "31.3.135.232" ascii //weight: 1
        $x_1_11 = "62.113.203.55" ascii //weight: 1
        $x_1_12 = "37.228.151.133" ascii //weight: 1
        $x_1_13 = "144.76.133.38" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Derbit_B_2147719571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derbit.B"
        threat_id = "2147719571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derbit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {b9 0a 00 00 00 be 42 57 07 00 f3 a5}  //weight: 3, accuracy: High
        $x_5_2 = {00 70 61 79 6c 6f 61 64 2e 64 6c 6c 00 5f 53 74 61 72 74 40 34 00}  //weight: 5, accuracy: High
        $x_1_3 = "185.121.177.177" ascii //weight: 1
        $x_1_4 = "185.121.177.53" ascii //weight: 1
        $x_1_5 = "45.63.25.55" ascii //weight: 1
        $x_1_6 = "111.67.16.202" ascii //weight: 1
        $x_1_7 = "142.4.204.111" ascii //weight: 1
        $x_1_8 = "142.4.205.47" ascii //weight: 1
        $x_1_9 = "31.3.135.232" ascii //weight: 1
        $x_1_10 = "62.113.203.55" ascii //weight: 1
        $x_1_11 = "37.228.151.133" ascii //weight: 1
        $x_1_12 = "144.76.133.38" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Derbit_D_2147722622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derbit.D!bit"
        threat_id = "2147722622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derbit"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "{BASECONFIG}" ascii //weight: 10
        $x_10_2 = "bcdfghklmnpqrstvwxzaeiouy%x%x%x%x%x%x" ascii //weight: 10
        $x_10_3 = {2e 64 6c 6c 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45}  //weight: 10, accuracy: High
        $x_10_4 = {2e 62 69 74 00 48 54 54 50 2f 31 2e 31 00 50 4f 53 54 00 47 45 54 00 43 6f 6e 6e 65 63 74 69 6f 6e 3a}  //weight: 10, accuracy: High
        $x_1_5 = "185.121.177.53" ascii //weight: 1
        $x_1_6 = "185.121.177.177" ascii //weight: 1
        $x_1_7 = "45.63.25.55" ascii //weight: 1
        $x_1_8 = "111.67.16.202" ascii //weight: 1
        $x_1_9 = "142.4.204.111" ascii //weight: 1
        $x_1_10 = "142.4.205.47" ascii //weight: 1
        $x_1_11 = "31.3.135.232" ascii //weight: 1
        $x_1_12 = "62.113.203.55" ascii //weight: 1
        $x_1_13 = "37.228.151.133" ascii //weight: 1
        $x_1_14 = "144.76.133.38" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}


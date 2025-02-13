rule TrojanProxy_Win32_Tinxy_A_2147614558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Tinxy.A"
        threat_id = "2147614558"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 38 20 74 09 48 80 38 20 75 fa 89 45 08 6a 2f 8d 85 10 cc ff ff 6a 3a}  //weight: 2, accuracy: High
        $x_2_2 = {50 6a 02 68 ?? ?? ?? ?? 57 ff d3 33 db 8b 46 04 83 c6 04 3b c3 75 bb}  //weight: 2, accuracy: Low
        $x_2_3 = {05 00 ff ff ff 56 50 57 ff 15 ?? ?? ?? ?? 8d 45 fc 56 50 68 00 01 00 00 53 57 ff 15}  //weight: 2, accuracy: Low
        $x_1_4 = {70 72 6f 63 65 73 73 2d 63 6c 69 63 6b 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {70 72 6f 63 65 73 73 2d 64 6f 6d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = "GET /search.php?p=%04d&s=%s&q=%s" ascii //weight: 1
        $x_1_7 = {2d 3e 43 6c 69 65 6e 74 3a 20 53 65 6e 74 20 25 6c 64 20 62 79 74 65 73 0a 00}  //weight: 1, accuracy: High
        $x_1_8 = {25 73 5c 54 69 6e 79 50 72 6f 78 79 5c 25 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Tinxy_B_2147616440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Tinxy.B"
        threat_id = "2147616440"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 05 00 ff ff ff 51 50 56 57 ff 15 74 10 40 00 57 ff 15 34 10 40 00 8d 45 ec 89 75 ec 50 c7 45 f0 a8 2b 40 00 89 5d f4 89 5d f8 ff 15 04 10 40 00 5f 5e 33 c0 5b c9 c2 10 00}  //weight: 10, accuracy: High
        $x_10_2 = "GET /search.php?p=%04d&s=%s&q=%s HTTP/1.1" ascii //weight: 10
        $x_10_3 = "%s\\TinyProxy\\%u" ascii //weight: 10
        $x_10_4 = "process-domain" ascii //weight: 10
        $x_10_5 = "process-clicks" ascii //weight: 10
        $x_1_6 = "www.search.yahoo" ascii //weight: 1
        $x_1_7 = "www.search.live." ascii //weight: 1
        $x_1_8 = "www.search.msn." ascii //weight: 1
        $x_1_9 = "www.google." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Tinxy_C_2147616668_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Tinxy.C"
        threat_id = "2147616668"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 45 ec 89 ?? ?? 50 c7 45 ?? ?? ?? ?? ?? 89 ?? ?? 89 ?? ?? ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b c9 c2 10 00}  //weight: 10, accuracy: Low
        $x_10_2 = "GET /search.php?p=%04d&s=%s&q=%s HTTP/1.1" ascii //weight: 10
        $x_10_3 = "%s\\TinyProxy\\%u" ascii //weight: 10
        $x_10_4 = "process-domain" ascii //weight: 10
        $x_10_5 = "process-clicks" ascii //weight: 10
        $x_1_6 = "www.search.yahoo" ascii //weight: 1
        $x_1_7 = "www.search.live." ascii //weight: 1
        $x_1_8 = "www.search.msn." ascii //weight: 1
        $x_1_9 = "www.google." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Tinxy_D_2147616669_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Tinxy.D"
        threat_id = "2147616669"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 45 fc d5 c6 45 fd ae c6 45 fe 8b c6 45 ff 48 ff 75 fc}  //weight: 2, accuracy: High
        $x_3_2 = {74 48 6a 10 8d 45 e8 53 50 e8 ?? ?? 00 00 83 c4 0c 66 c7 45 e8 02 00 89 5d ec 68 82 23 00 00 e8}  //weight: 3, accuracy: Low
        $x_1_3 = "/search.php?p=%04d&s=%s&" ascii //weight: 1
        $x_1_4 = {26 71 3d 00 77 77 77 2e 73 65 61 72 63 68 2e 6c 69 76 65 2e}  //weight: 1, accuracy: High
        $x_1_5 = "/pagead/iclk" ascii //weight: 1
        $x_2_6 = {70 72 6f 63 65 73 73 2d 64 6f 6d 61 69 6e 00 00 70 72 6f 63 65 73 73 2d 63 6c 69 63 6b 73}  //weight: 2, accuracy: High
        $x_2_7 = {3c 73 70 61 6e 3e 00 00 75 73 65 72 2d 61 67 65}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Tinxy_E_2147619192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Tinxy.E"
        threat_id = "2147619192"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {39 7d 0c 75 07 be ?? ?? 40 00 eb 1d 83 7d 0c 01 75 07 be ?? ?? 40 00 eb 10 83 7d 0c 02 be ?? ?? 40 00 74 05}  //weight: 2, accuracy: Low
        $x_2_2 = "GET /search.php?p=%04d&s=%s&v=%s&t=%ld&q=%s HTTP/1.1" ascii //weight: 2
        $x_1_3 = "process-clicks" ascii //weight: 1
        $x_1_4 = {3f 70 3d 00 26 70 3d 00 3f 71 3d 00 26 71 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 2e 61 73 73 65 6d 62 6c 79 00}  //weight: 1, accuracy: High
        $x_1_6 = "123812938y1293812y39128y312983.dat" ascii //weight: 1
        $x_1_7 = {2f 75 72 6c 3f [0-5] 2f 61 63 6c 6b 3f}  //weight: 1, accuracy: Low
        $x_1_8 = {49 6e 74 65 72 6e 25 73 72 6c 41 00 65 74 43 72 61 63 6b 55 00}  //weight: 1, accuracy: High
        $x_1_9 = {70 72 6f 25 73 61 69 6e [0-16] 63 65 73 73 2d 64 6f 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Tinxy_F_2147621160_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Tinxy.F"
        threat_id = "2147621160"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 1e 51 68 98 01 22 00 50 ff 15}  //weight: 3, accuracy: High
        $x_1_2 = {83 f8 01 89 45 f8 7d 0b 8b c7 47 83 f8 64 7d 03 53 eb dd}  //weight: 1, accuracy: High
        $x_1_3 = {83 c0 ac 56 50 53 ff 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8d 45 fc 56 50 6a 50}  //weight: 1, accuracy: Low
        $x_1_4 = {50 4e 50 5f 54 44 49 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Tinxy_G_2147621349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Tinxy.G"
        threat_id = "2147621349"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 72 6f 63 65 73 73 2d 63 6c 69 63 6b 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "GET /search.php?p=%04d&s=%s&v=%s&q=%s" ascii //weight: 1
        $x_1_3 = {05 00 ff ff ff ?? ?? ?? ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 00 01 00 00 ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {85 db 75 07 be ?? ?? ?? ?? eb 1b 83 fb 01 75 07 be ?? ?? ?? ?? eb 0f 83 fb 02 be ?? ?? ?? ?? 74 05 be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanProxy_Win32_Tinxy_H_2147621435_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Tinxy.H"
        threat_id = "2147621435"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 72 6f 63 65 73 73 2d 63 6c 69 63 6b 73 3a 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 72 6f 63 65 73 73 2d 72 65 66 65 72 65 72 3a 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 47 59 4d 41 53 00}  //weight: 1, accuracy: High
        $x_2_4 = {c6 47 ff 25 c6 07 32 83 c4 10 c6 47 01 30}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


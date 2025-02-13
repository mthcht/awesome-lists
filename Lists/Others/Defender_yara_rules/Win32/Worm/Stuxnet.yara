rule Worm_Win32_Stuxnet_A_2147636327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Stuxnet.A"
        threat_id = "2147636327"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Stuxnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 04 8d 4d 10 51 83 c0 08 50 ff 75 08 ff d6 85 c0 75 04 33 c0 eb 21 8b 47 50 85 c0 74 17 8d 4d 0c 51 6a 04 8d 4d 10 51 83 c0 10 50 ff 75 08 ff d6}  //weight: 3, accuracy: High
        $x_3_2 = {76 15 8b c8 83 e1 0f 83 c1 42 66 89 4c 75 c0 c1 e8 04 46 85 c0 77 eb 33 c0 66 89 44 75 c0 33 f6 8d 45 c0 50 6a 00 6a 00}  //weight: 3, accuracy: High
        $x_3_3 = {bb 4d 5a 00 00 8b c3 66 39 07 74 ?? 8b 75 08 33 d2 8b cf 85 f6 76 0f 8a 01 34 4e 2a c2 88 01 41 4e 0f b6 d0 75}  //weight: 3, accuracy: Low
        $x_3_4 = {6a 40 8d 45 b8 50 53 ff d6 85 c0 74 ?? 83 7d fc 40 75 50 b8 4d 5a 00 00 66 39 45 b8 75}  //weight: 3, accuracy: Low
        $x_1_5 = "SHELL32.DLL.ASLR." ascii //weight: 1
        $x_1_6 = "ncacn_ip_tcp:%s" ascii //weight: 1
        $x_1_7 = "Context=\"%s\"><Exec><Command>" ascii //weight: 1
        $x_1_8 = "%SystemRoot%\\inf\\*.pnf" ascii //weight: 1
        $n_100_9 = {8b 44 24 0c 03 c6 30 08 c1 c9 ?? 8b c1 0f af c1 33 d2 bf ?? ?? ?? ?? f7 f7 8b d1 69 d2 ?? ?? ?? ?? 8d 44 10 01 33 c8 46 3b 74 24 10 72 d2}  //weight: -100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Stuxnet_B_2147636328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Stuxnet.B"
        threat_id = "2147636328"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Stuxnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 04 00 00 00 0f b7 04 4f 66 83 f8 30 72 b9 66 83 f8 39 77 b3 0f b7 c0 8d 44 30 d0 99}  //weight: 1, accuracy: High
        $x_1_2 = {ff d7 ff d3 50 6a 01 6a 1c 56 ff d7 56 6a 02 6a 06 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


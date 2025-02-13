rule Worm_Win32_QQnof_A_2147617485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/QQnof.A"
        threat_id = "2147617485"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "QQnof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4e 20 8b 3d a8 21 40 00 6a 00 6a 64 68 d8 00 00 00 51 ff d7 8b 56 20 6a 00 6a 64 68 cf 00 00 00 52 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {62 69 61 6f 6a 69 00 00 4e 6f 74 69 66 79 57 6e 64 00 00 00 d6 d8 c6 f4 c7 b0 b6 d4 b8 c3 cf ee b2 c9 d3 c3 cf e0 cd ac b2 d9 d7 f7 2c b2 bb d4 d9 bd f8 d0 d0 cc e1 ca be 00 00 00 b2 a2 bd ab c6 e4 bc d3 c8 eb d0 c5 c8 ce b2 e5 bc fe c1 d0 b1 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_QQnof_A_2147617485_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/QQnof.A"
        threat_id = "2147617485"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "QQnof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 50 6a 00 6a 00 ff d3 68 ff 01 00 00 ff 15 ?? ?? ?? ?? 68}  //weight: 10, accuracy: Low
        $x_1_2 = "http://www.rjhoutai.cn" ascii //weight: 1
        $x_1_3 = "http://user.qbar.qq.com/" ascii //weight: 1
        $x_1_4 = "http://minisite.qq.com/all/allinone.shtml" ascii //weight: 1
        $x_10_5 = {26 61 6c 65 78 61 3d 00 26 6c 69 61 6e 6d 65 6e 67 3d 00 00 26 6d 61 63 3d 00 00 00 26 76 65 72 3d 00 00 00 69 6e 73 74 61 6c 6c 00 61 63 74 69 6f 6e 3d 00 2f 68 61 69 6c 69 61 6e 67 2e 61 73 70 78 3f 00 47 4f 4f 47 4c 45}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


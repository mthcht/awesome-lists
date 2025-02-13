rule Trojan_Win32_Pucodex_A_2147631466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pucodex.A"
        threat_id = "2147631466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pucodex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e0 07 8b 4d f8 c1 e9 19 0b c1 89 45 f8 8b ?? fc 0f be 02 33 45 f8}  //weight: 1, accuracy: Low
        $x_1_3 = {3d e5 03 00 00 [0-8] 68 e8 03 00 00 ff 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_4 = {0f be 44 05 d4 83 e8 30 0f af 45 fc 99 6a 1a 59 f7 f9 83 c2 61}  //weight: 1, accuracy: High
        $x_1_5 = {c6 45 f4 76 c6 45 f5 73 c6 45 f6 6d c6 45 f7 6f c6 45 f8 6e c6 45 f9 2e c6 45 fa 65 c6 45 fb 78 c6 45 fc 65}  //weight: 1, accuracy: High
        $x_1_6 = {c6 45 f8 61 c6 45 f9 76 c6 45 fa 70 c6 45 fb 2e c6 45 fc 65 c6 45 fd 78 c6 45 fe 65}  //weight: 1, accuracy: High
        $x_1_7 = "%s?act=%s&uid=%s" ascii //weight: 1
        $x_1_8 = {6e 65 78 74 63 61 6c 6c 00 00 00 00 74 61 73 6b 5f 69 64 00 74 61 73 6b 5f 74 79 70 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Pucodex_B_2147637480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pucodex.B"
        threat_id = "2147637480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pucodex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "image/pjpeg" ascii //weight: 1
        $x_1_2 = "%s?act=%s&uid=%s&id=%s" ascii //weight: 1
        $x_1_3 = "killDate" ascii //weight: 1
        $x_1_4 = "botid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Kimsuk_A_2147683162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kimsuk.A!dha"
        threat_id = "2147683162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kimsuk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 85 db f3 a4 7e 0e 8a 0c 10 80 f1 99 88 0c 10 40 3b c3 7c f2}  //weight: 1, accuracy: High
        $x_1_2 = {8a 4c 30 ff 30 0c 30 48 85 c0 7f f4 80 36 ac c6 04 37 00 5f}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 85 f6 7e 09 80 34 38 99 40 3b c6 7c f7 8b c7}  //weight: 1, accuracy: High
        $x_1_4 = "&readresponse=0&saveattachments=1&saveinsent=1&linkattachments=0&recaptcha_response_field=&" ascii //weight: 1
        $x_1_5 = {68 a9 04 bc 6a e8 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 51 68 cf 72 18 6c e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 52 68 f2 e2 b7 1b e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 68 99 9f 81 de e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 51 68 56 07 cc e5 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 49 00 0f be 14 39 03 f2 8b c6 c1 e8 0e c1 e6 12 03 f0 8b c1 47 8d 58 01 8a 10 40 84 d2 75 f9 2b c3 3b f8 72 dd 3b 74 24 24 74 0f 8b 44 24 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Kimsuk_B_2147683181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kimsuk.B"
        threat_id = "2147683181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kimsuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4c 10 ff 8a 1c 10 32 d9 88 1c 10 48 85 c0 7f ef 8a 02 5f 34 ac 5e 88 02 c6 04 2a 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 04 1a 03 f0 8b fa 8b ce 33 c0 c1 e9 0e c1 e6 12 03 f1 83 c9 ff 43 f2 ae f7 d1 49 3b d9 72 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kimsuk_C_2147705911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kimsuk.C!dha"
        threat_id = "2147705911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kimsuk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4c 10 ff 8a 1c 10 32 d9 88 1c 10 48 85 c0 7f ef 8a 02 5f 34 ac 5e 88 02 c6 04 2a 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff b0 f6 a2 f5 b4 e6 a3 ff bc d3 ba d4 a7 d3 b2 d5 b0 c2 9e c8 ad df ac c5 aa c4 f1 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


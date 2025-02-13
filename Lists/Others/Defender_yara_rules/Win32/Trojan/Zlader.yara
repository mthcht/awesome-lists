rule Trojan_Win32_Zlader_A_2147696748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlader.A"
        threat_id = "2147696748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 9b ff 87 ff ab 35 15 00 14 00 ab 05 ff ff 05 00 ab 83 f0 0a ab 2d 37 00 0d 00}  //weight: 1, accuracy: High
        $x_1_2 = {2d ad ff 90 ff ab 35 35 00 1b 00 ab 05 11 00 ed ff ab 35 05 00 04 00 ab 2d 16 00 18 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 8e ff 8a ff ab 35 1c 00 14 00 ab 05 05 00 9f ff}  //weight: 1, accuracy: High
        $x_1_4 = {2d 89 ff 92 ff ab 35 1e 00 0e 00 ab 05 97 ff 14 56}  //weight: 1, accuracy: High
        $x_1_5 = {2d 73 00 e7 a9 ab 8b 7d fc 66 c7 47 28 22 00 66 c7 47 2a 25 00}  //weight: 1, accuracy: High
        $x_1_6 = {58 ff d0 83 e8 04 81 3c 38 2e 65 78 65 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Zlader_ARA_2147835014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlader.ARA!MTB"
        threat_id = "2147835014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {85 c9 7c 2a 8b 35 88 1c 41 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8b 15 00 10 41 00 8d 04 80 03 c0 2b d0 8a 04 0a 30 04 0e 41 3b 0d 9c 1c 41 00 76 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlader_ARA_2147835014_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlader.ARA!MTB"
        threat_id = "2147835014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d ec 83 c1 01 89 4d ec 8b 55 ec 3b 15 5c 50 40 00 73 2d 8b 45 ec 99 b9 0a 00 00 00 f7 f9 8b 45 f8 0f be 0c 10 8b 15 44 50 40 00 03 55 ec 0f be 02 33 c1 8b 0d 44 50 40 00 03 4d ec 88 01 eb bf}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


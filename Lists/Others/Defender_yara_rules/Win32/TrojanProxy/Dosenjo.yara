rule TrojanProxy_Win32_Dosenjo_A_2147803989_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Dosenjo.A"
        threat_id = "2147803989"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dosenjo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 6e 66 c7 44 24 10 02 00 ff 15 ?? ?? ?? ?? 6a 10 8d 4c 24 10 51 57}  //weight: 2, accuracy: Low
        $x_2_2 = {85 ff 75 01 42 40 3b c1 7c ef 83 fa 05 7d 22}  //weight: 2, accuracy: High
        $x_1_3 = {63 61 63 68 69 6e 67 44 65 6e 79 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 26 69 70 3d 25 73 26 6d 6f 64 65 3d 25 73 26 64 6c 6c 3d 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Dosenjo_B_2147804126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Dosenjo.B"
        threat_id = "2147804126"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dosenjo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?action=serp&w=%s&id=%s&acc=%d&nc=%s" ascii //weight: 1
        $x_1_2 = "%s&ip=%s&mode=%s&dll=%d" ascii //weight: 1
        $x_1_3 = "?cachingDeny=" ascii //weight: 1
        $x_1_4 = "csrss%s.dll" ascii //weight: 1
        $x_1_5 = "110:TCP:*:Enabled:svchost" ascii //weight: 1
        $x_1_6 = "User-Agent: Mozilla Compatible Ppc Linker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanProxy_Win32_Dosenjo_C_2147804146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Dosenjo.C"
        threat_id = "2147804146"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dosenjo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 6e 66 c7 45 ec 02 00 ff 15 ?? ?? ?? ?? 83 65 f0 00 6a 10 5f 66 89 45 ee 57 8d 45 ec 50 53}  //weight: 3, accuracy: Low
        $x_3_2 = {8b 4d 94 8a 4c 0d 98 30 08 ff 45 94 83 7d 94 20 72 04 83 65 94 00 40 80 38 00 75 e4}  //weight: 3, accuracy: High
        $x_1_3 = "?cachingDeny=" ascii //weight: 1
        $x_1_4 = "BUFBUF NOT ENC" ascii //weight: 1
        $x_1_5 = "fuseaction=sitesearch.results" ascii //weight: 1
        $x_2_6 = {3f 71 75 65 72 79 3d 00 2f 66 75 6c 6c 73 65 61 72 63 68 00 53 70 65 63 69 61 6c 3a 53 65 61 72 63 68 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Dosenjo_D_2147804147_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Dosenjo.D"
        threat_id = "2147804147"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dosenjo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff ff 02 00 8b f4 6a 6e ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 66 89 85 ?? ?? ff ff c7 85 ?? ?? ff ff 00 00 00 00 8b f4 6a 10 8d 85 ?? ?? ff ff 50 8b 8d ?? ?? ff ff 51 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {b8 cc cc cc cc f3 ab a0 ?? ?? ?? ?? 88 85 ?? ?? ff ff b9 ?? ?? ?? ?? 33 c0 8d bd ?? ?? ff ff f3 ab 66 ab aa 8b f4 6a 00 6a 21 8d 85 ?? ?? ff ff 50 6a 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = "?cachingDeny=" ascii //weight: 2
        $x_1_4 = {83 c0 0d 99 b9 1a 00 00 00 f7 f9 8a 44 15}  //weight: 1, accuracy: High
        $x_1_5 = "110:TCP:*:Enabled:svchost" ascii //weight: 1
        $x_1_6 = {00 53 76 63 68 6f 73 74 49 44 00}  //weight: 1, accuracy: High
        $x_1_7 = "\\SverjnyyCbyvpl\\FgnaqneqCebsvyr\\TybonyylBcraCbegf\\Yvfg\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


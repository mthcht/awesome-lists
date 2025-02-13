rule TrojanProxy_Win32_Sefbov_A_2147622786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Sefbov.A"
        threat_id = "2147622786"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefbov"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f5 5a 75 04 c6 45 f5 5b}  //weight: 1, accuracy: High
        $x_1_2 = {68 28 0a 00 00 a3 08 30 40 00}  //weight: 1, accuracy: High
        $x_1_3 = "89.107.104" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanProxy_Win32_Sefbov_B_2147626502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Sefbov.B"
        threat_id = "2147626502"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefbov"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 18 c6 45 f5 5a}  //weight: 1, accuracy: High
        $x_1_2 = {68 28 0a 00 00 a3 08 ?? (40 00|00 10)}  //weight: 1, accuracy: Low
        $x_1_3 = "89.107.104" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanProxy_Win32_Sefbov_D_2147638638_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Sefbov.D"
        threat_id = "2147638638"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefbov"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 62 73 73 72 65 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 61 69 6c 61 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 3a 32 35 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 63 62 73 73 5c 43 61 6c 6c 42 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 43 61 6c 6c 42 61 63 6b 2f 53 6f 6d 65 53 63 72 69 70 74 73 2f 6d 67 73 4e 65 77 50 65 65 72 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 80 00 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 02 e8 ?? ?? ?? ?? 0b c0 0f 84 ?? ?? ?? ?? 8b f8 68 ?? ?? ?? ?? 6a 00 6a 02 e8 ?? ?? ?? ?? 90 8b f0 68 ?? ?? ?? ?? 6a 00 68 00 00 10 00 e8 ?? ?? ?? ?? 8b d8 57 e8 ?? ?? ?? ?? 6a ff 53 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanProxy_Win32_Sefbov_E_2147646324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Sefbov.E"
        threat_id = "2147646324"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefbov"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".DEFAULT\\Software\\AMService\\CallBack" ascii //weight: 1
        $x_1_2 = "CheckPort25Result" ascii //weight: 1
        $x_1_3 = "executePredefinedQuery:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


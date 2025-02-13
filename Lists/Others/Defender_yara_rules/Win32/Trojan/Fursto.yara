rule Trojan_Win32_Fursto_A_2147598160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fursto.gen!A"
        threat_id = "2147598160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fursto"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b6 ba b9 96 93 8b 9a 8d d1 9b 93 93 00}  //weight: 10, accuracy: High
        $x_10_2 = {b2 ac b6 ba b7 9a 93 8f 9a 8d d1 9b 93 93 00}  //weight: 10, accuracy: High
        $x_10_3 = {ac 90 99 8b 88 9e 8d 9a a3 a3 b2 96 9c 8d 90 8c 90 99 8b a3 a3 b9 96 93 8b 9a 8d 00}  //weight: 10, accuracy: High
        $x_10_4 = {ac 90 99 8b 88 9e 8d 9a a3 b2 96 9c 8d 90 8c 90 99 8b a3 b9 96 93 8b 9a 8d 00}  //weight: 10, accuracy: High
        $x_10_5 = {b1 9a 9a 9b ac 9a 91 9b b6 91 99}  //weight: 10, accuracy: Low
        $x_5_6 = {74 0c f6 d0 88 03 8a 43 01 43 84 c0 75 f4}  //weight: 5, accuracy: High
        $x_5_7 = {74 0a f6 d0 88 07 8a 47 01 47 eb f2}  //weight: 5, accuracy: High
        $x_5_8 = {74 18 8b 4d fc 0f be 11 f7 d2 8b 45 fc 88 10 8b 4d fc 83 c1 01 89 4d fc eb de}  //weight: 5, accuracy: High
        $x_5_9 = {74 18 8b 45 fc 0f be 08 f7 d1 8b 55 fc 88 0a 8b 45 fc 83 c0 01 89 45 fc eb de}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fursto_C_2147598161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fursto.C!dll"
        threat_id = "2147598161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fursto"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 75 fc 75 32 ff 75 0c e8 ?? ?? 00 00 84 c0 59 74 25 be ?? ?? 00 10 56 ff 15 ?? ?? 00 10 50 8b 45 0c 05 ?? 05 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fursto_D_2147598162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fursto.D"
        threat_id = "2147598162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fursto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 eb e4 68 ?? ?? 40 00 56 ff 15 ?? ?? 40 00 3b c3 74 49 53 56 50 6a 03 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d6 eb ea 68 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 3b c3 75 06 6a 01 58 5e eb c2 53 53 53 ff d0 6a f1 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d3 eb e4 68 ?? ?? 40 00 57 ff 15 ?? ?? 40 00 3b c6 74 49 56 57 50 6a 03 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fursto_E_2147598163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fursto.E"
        threat_id = "2147598163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fursto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 55 ff d7 85 c0 74 57 68 ?? ?? 00 10 55 56 ff d7 85 c0 74 4a 8b 3d ?? ?? 00 10 6a 00 56 ff 15 ?? ?? 00 10 85 c0 74 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


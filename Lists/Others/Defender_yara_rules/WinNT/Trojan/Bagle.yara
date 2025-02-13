rule Trojan_WinNT_Bagle_2147596564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Bagle"
        threat_id = "2147596564"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Bagle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 28 03 75 18 8b 4d 2c (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_2 = {80 36 33 46 49 0b c9 75 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Bagle_B_2147602456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Bagle.gen!B"
        threat_id = "2147602456"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Bagle"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 01 b8 c6 41 01 01 88 41 02 88 41 03 c6 41 04 c0 c6 41 05 c2 c6 41 06 08 88 41 07 8b 45 08 0f 22 c0 fb 83 45 10 04}  //weight: 1, accuracy: High
        $x_1_2 = {75 18 c6 40 fb e9 8b 49 08 2b c8 89 48 fc 8b 45 08 66 ba eb f9 66 89 10 eb 3a 83 fa 02 75 18 c6 40 fb e9}  //weight: 1, accuracy: High
        $x_1_3 = {83 7d e4 08 73 2c 8b 45 e4 ff 34 85 ?? ?? ?? ?? ff 75 e0 ff 15 ?? ?? ?? ?? 59 59 85 c0 75 0e b8 22 00 00 c0 83 4d fc ff e9 ?? 00 00 00 ff 45 e4 eb ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_WinNT_Bagle_C_2147624936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Bagle.gen!C"
        threat_id = "2147624936"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Bagle"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\bisoft" ascii //weight: 10
        $x_10_2 = "\\\\.\\sK9Ou0s" ascii //weight: 10
        $x_10_3 = {61 76 7a 2e 65 78 65 00 42 61 63 6b 57 65 62 2d 34 34 37 36 38 32 32 2e 65 78 65 00 62 64 61 67 65 6e 74 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\Security Center\\Svc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Bagle_D_2147624937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Bagle.gen!D"
        threat_id = "2147624937"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Bagle"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 5c 57 49 4e 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 5c 5c 2e 5c 00 53 6f 66 74 77 61 72 65 5c 62 69 73 6f 66 74 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 00 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


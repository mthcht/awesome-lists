rule Trojan_WinNT_Goriadu_A_2147640245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Goriadu.gen!A"
        threat_id = "2147640245"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Goriadu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 69 6c 65 5f 68 65 61 6c 74 68 5f 69 6e 66 6f 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 70 6c 6f 61 64 5f 74 6f 6b 65 6e 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 75 70 65 72 6b 69 6c 6c 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {67 65 6f 2e 6b 61 73 70 65 72 73 6b 79 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 77 77 2e 64 75 62 61 2e 6e 65 74 00}  //weight: 1, accuracy: High
        $x_10_6 = "\\DosDevices\\netsflt" wide //weight: 10
        $x_10_7 = {45 3a 5c 70 61 73 73 74 68 72 75 5c [0-7] 5c 64 72 69 76 65 72 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c [0-7] 2e 70 64 62 00}  //weight: 10, accuracy: Low
        $x_10_8 = {80 a6 b4 00 00 00 00 81 c6 a4 00 00 00 56 ff 15 ?? ?? ?? ?? 8b c7 5f 5e 5d c2 18 00 30 01 80 [0-2] 48 0f ?? ?? eb [0-4] 75 ?? 80 [0-2] 6f 75 ?? 6a 02 eb ?? 83 ?? 02 75 ?? 80 [0-2] 73 75 ?? 6a 03 eb ?? 83 ?? 03 75 ?? 80 [0-2] 74 75 ?? 6a 04 eb ?? 83 ?? 04 75 ?? 80 [0-2] 3a 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Goriadu_B_2147648181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Goriadu.gen!B"
        threat_id = "2147648181"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Goriadu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "file_health_info.php" ascii //weight: 3
        $x_1_2 = "geo.kaspersky.com" ascii //weight: 1
        $x_2_3 = "cu010.www.duba.net" ascii //weight: 2
        $x_3_4 = "\\DosDevices\\Passthru" wide //weight: 3
        $x_2_5 = "NdisGetPoolFromPacket" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


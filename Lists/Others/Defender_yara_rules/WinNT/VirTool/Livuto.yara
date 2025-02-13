rule VirTool_WinNT_Livuto_2147598253_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Livuto"
        threat_id = "2147598253"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Livuto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 04 80 00 ?? 40 80 38 00 75 f7 b0 01 c2 04 00 8b 44 24 04 eb 06 66 83 00 ?? 40 40 66 83 38 00 75 f4 b0 01 c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Livuto_2147604763_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Livuto.gen!sys"
        threat_id = "2147604763"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Livuto"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7e 13 8a 14 06 80 fa 22 74 06 80 ea ?? 88 14 06 46 3b f1 7c ed}  //weight: 3, accuracy: Low
        $x_1_2 = {3d 24 0c 0b 83 0f 84}  //weight: 1, accuracy: High
        $x_1_3 = {61 75 74 6f 6c 69 76 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_4 = "Rootkit: OnUnload" ascii //weight: 1
        $x_1_5 = {7e 13 8a 0c 02 84 c9 74 0c fe c1 88 0c 02 42 3b 54 24 08 7c ed c2 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Livuto_A_2147607328_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Livuto.gen!A"
        threat_id = "2147607328"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Livuto"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 65 da 00 c6 45 d4 ea c6 45 d9 08 c6 45 db 90 c6 45 dc 90 c6 45 dd 90 89 4d d5 fa}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 e4 55 c6 45 e5 8b c6 45 e6 ec c6 45 e7 6a c6 45 e9 68 c6 45 ea aa c6 45 eb aa}  //weight: 1, accuracy: High
        $x_2_3 = {61 00 62 00 6f 00 75 00 74 00 2e 00 62 00 6c 00 61 00 6e 00 6b 00 2e 00 6c 00 61 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Livuto_B_2147609842_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Livuto.gen!B"
        threat_id = "2147609842"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Livuto"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e3 e5 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6b 00 7a 00 64 00 68 00 2e 00 63 00 6f 00 6d 00 2f 00 3f 00 67 00 00 00 00 00 61 00 62 00 6f 00 75 00 74 00 3a 00 62 00 6c 00 61 00 6e 00 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {32 00 33 00 2e 00 00 00 31 00 32 00 38 00 31 00 32 00 36 00 2e 00 00 00 38 00 37 00 34 00 39 00 2e 00 00 00 39 00 35 00 33 00 33 00 2e 00 00 00 7a 00 68 00 61 00 6f 00 64 00 61 00 6f 00 31}  //weight: 1, accuracy: High
        $x_1_3 = "\\SystemRoot\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_4 = "http://www.baidu.com/index.php?tn=wsebsearch_pg" wide //weight: 1
        $x_1_5 = "\\DosDevices\\ClanAvb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


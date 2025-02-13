rule Trojan_Win32_Monroda_A_2147602493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Monroda.gen!A"
        threat_id = "2147602493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Monroda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "\\under construction\\thevirus\\thevirus\\thevirusdlg.cpp" ascii //weight: 3
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "Welcome To %s" ascii //weight: 1
        $x_3_4 = {44 61 74 65 20 41 6e 64 20 54 69 6d 65 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 00 00 00 49 72 66 61 6e 76 69 65 77}  //weight: 3, accuracy: High
        $x_3_5 = {44 61 74 65 20 41 6e 64 20 54 69 6d 65 ?? ?? ?? 57 69 6e 64 6f 77 73 20 54 61 73 6b 20 4d 61 6e 61 67 65 72 ?? ?? ?? ?? ?? ?? ?? ?? 52 65 67 69 73 74 72 79 20 45 64 69 74 6f 72 ?? ?? ?? ?? ?? 49 72 66 61 6e 76 69 65 77 ?? ?? ?? 47 6f 6f 67 6c 65 20 54 61 6c 6b ?? ?? ?? ?? ?? 4d 61 63 72 6f 6d 65 64 69 61}  //weight: 3, accuracy: Low
        $x_3_6 = {41 64 6f 62 65 00 00 00 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c ?? ?? ?? ?? 57 69 6e 64 6f 77 73 20 4d 65 64 69 61 20 50 6c 61 79 65 72 ?? ?? ?? ?? ?? ?? ?? ?? 57 69 6e 61 6d 70 00 00 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 00 00 00 00 4d 69 63 72 6f 73 6f 66 74 20 45 78 63 65 6c}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Vefisi_A_2147597814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vefisi.gen.dll!A"
        threat_id = "2147597814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vefisi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?id=%s&time=%s" ascii //weight: 1
        $x_1_2 = "?id=%s&Count=%d" ascii //weight: 1
        $x_1_3 = "?id=%s&cab=%s" ascii //weight: 1
        $x_1_4 = "?id=%s&t=%s&mac=%s" ascii //weight: 1
        $x_1_5 = "png?id=%s&t=%s" ascii //weight: 1
        $x_1_6 = {57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 00 00 25 73 5c 25 73 2e 6c 6e}  //weight: 1, accuracy: High
        $x_1_7 = {5c 4d 69 63 72 6f 73 6f 66 74 00 00 25 30 34 64}  //weight: 1, accuracy: High
        $x_1_8 = {5c 4d 69 63 72 6f 73 6f 66 74 00 25 30 34 64}  //weight: 1, accuracy: High
        $x_1_9 = {25 73 5c 6c 6f 67 2e 69 6e 69 00 00 25 73 5c}  //weight: 1, accuracy: High
        $x_1_10 = {6c 6f 67 2e 69 6e 69 00 56 65 72 73 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_11 = {5b 56 65 72 73 69 6f 6e 5d 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Vefisi_A_2147597816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vefisi.gen!A"
        threat_id = "2147597816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vefisi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sc.exe delete KWatchSvc" ascii //weight: 1
        $x_2_2 = {c7 44 24 28 02 00 00 00 89 5c 24 2c 89 5c 24 30 89 5c 24 34 89 5c 24 38 89 44 24 3c 89 5c 24 40 89 5c 24 14}  //weight: 2, accuracy: High
        $x_2_3 = "sc.exe stop KWatchSvc" ascii //weight: 2
        $x_2_4 = {6b 61 76 33 32 2e 65 78 65 00 00 00 61 76 70 2e}  //weight: 2, accuracy: High
        $x_2_5 = {4b 69 6c 6c 62 6f 78 00 49 63 65 53 77 6f 72 64}  //weight: 2, accuracy: High
        $x_1_6 = {2e 6c 6e 6b 00 00 25 73 5c 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}


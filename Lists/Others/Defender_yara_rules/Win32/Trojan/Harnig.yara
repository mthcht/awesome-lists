rule Trojan_Win32_Harnig_A_90331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Harnig.gen!A"
        threat_id = "90331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 3f 63 3d 25 64 00 25 73 25 73}  //weight: 1, accuracy: High
        $x_1_2 = {0f 85 c5 00 00 00 8b 35 a8 10 14 13 bf 00 04}  //weight: 1, accuracy: High
        $x_2_3 = {25 73 25 73 26 69 64 3d 25 64 26 63 3d 25 64 00 25 75 00 00 25 73 25 73 25 73 00 00 25 73 3f 63}  //weight: 2, accuracy: High
        $x_2_4 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Harnig_B_90332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Harnig.gen!B"
        threat_id = "90332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 70 68 70 00 3d 61 64 76}  //weight: 2, accuracy: High
        $x_2_2 = {3e 20 6e 75 6c 00 00 2f 63 20 64 65 6c 20}  //weight: 2, accuracy: High
        $x_2_3 = {43 4f 4d 53 50 45 43 00 6e 65 77 6c 31}  //weight: 2, accuracy: High
        $x_2_4 = "http://%s/progs/%s/" ascii //weight: 2
        $x_2_5 = {2e 65 78 65 00 25 64 00 00 43 3a 5c}  //weight: 2, accuracy: High
        $x_3_6 = {2e 65 78 65 00 00 00 5c ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65 00 00 00 5c}  //weight: 3, accuracy: Low
        $x_1_7 = {77 69 6e 69 6e 65 74 2e 64 6c 6c 00 4f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_8 = {68 70 00 61 64 76}  //weight: 1, accuracy: High
        $x_1_9 = {26 63 6f 64 65 32 3d 00}  //weight: 1, accuracy: High
        $x_1_10 = {26 63 6f 64 65 31 3d 00}  //weight: 1, accuracy: High
        $x_1_11 = ".php?adv=" ascii //weight: 1
        $x_1_12 = "GetSystemDefaultLangID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Harnig_C_91511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Harnig.gen!C"
        threat_id = "91511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://213." ascii //weight: 1
        $x_1_2 = "/dladv" ascii //weight: 1
        $x_1_3 = "/dl/" ascii //weight: 1
        $x_1_4 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_5 = "&code2=" ascii //weight: 1
        $x_1_6 = ".php?code1=" ascii //weight: 1
        $x_1_7 = "dluniq" ascii //weight: 1
        $x_1_8 = {2e 74 78 74 00 5c}  //weight: 1, accuracy: High
        $x_1_9 = "tool.exe" ascii //weight: 1
        $x_1_10 = "tool.txt" ascii //weight: 1
        $x_1_11 = "tibs.php" ascii //weight: 1
        $x_1_12 = "tibs.exe" ascii //weight: 1
        $x_1_13 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_14 = "RegisterServiceProcess" ascii //weight: 1
        $x_1_15 = "ObtainUserAgentString" ascii //weight: 1
        $x_1_16 = "InternetOpen" ascii //weight: 1
        $x_1_17 = "GetSystemDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}


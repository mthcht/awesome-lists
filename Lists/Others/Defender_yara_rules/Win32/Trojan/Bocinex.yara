rule Trojan_Win32_Bocinex_A_2147654778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bocinex.gen!A"
        threat_id = "2147654778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bocinex"
        severity = "Mid"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 c4 3c 00 00 00 50 c7 45 c8 40 04 00 00 89 75 cc 89 75 d0 c7 45 d4 ?? ?? ?? ?? c7 45 d8 ?? ?? ?? ?? 89 75 dc 89 75 e0 89 75 e4 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "dload.asia:8332/ -u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bocinex_B_2147656837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bocinex.gen!B"
        threat_id = "2147656837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bocinex"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 08 6a 00 68 00 00 00 80 6a 00 6a 00 51 50 89 45 ec ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 f8 6a 00 68 00 00 00 80 6a 00 6a 00 8b 45 08 50 8b 4d f8 51 ff 15}  //weight: 1, accuracy: High
        $x_2_3 = "\\CurrentVersion\\Policies\\Explorer\\run" ascii //weight: 2
        $x_5_4 = ".exe -g yes -o http://" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


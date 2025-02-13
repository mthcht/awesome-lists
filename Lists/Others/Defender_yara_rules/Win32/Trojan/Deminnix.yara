rule Trojan_Win32_Deminnix_A_2147683368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deminnix.gen!A"
        threat_id = "2147683368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deminnix"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b1 6f b2 73 80 3c 37 3c 75 2e 38 4c 37 01 75 28 80 7c 37 02 70 75 21 80 7c 37 03 74 75 1a 80 7c 37 04 69 75 13 38 4c 37 05 75 0d 80 7c 37 06 6e 75 06 38 54 37 07 74 09 83 c7 01 3b f8 72 c5 eb 49 68 ff 07 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {76 75 80 3c 33 3c 75 31 80 7c 33 01 6f 75 2a 80 7c 33 02 70 75 23 80 7c 33 03 74 75 1c 80 7c 33 04 69 75 15 80 7c 33 05 6f 75 0e 80 7c 33 06 6e 75 07 80 7c 33 07 73 74 07 43 3b d8 72 c4 eb 37 68 ff 07 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {0f be 42 05 83 f8 6f 75 6e 8b 4d ?? 03 4d ?? 0f be 51 06 83 fa 6e 75 5f 8b 45 ?? 03 45 ?? 0f be 48 07 83 f9 73 75 50 c6 85 ?? ?? ?? ?? 00 68 ff 07 00 00}  //weight: 2, accuracy: Low
        $x_1_4 = "SearchIndexer32.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Deminnix_B_2147683474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deminnix.gen!B"
        threat_id = "2147683474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deminnix"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 64 24 6c 6a 2e 89 6e 18 89 5e 14 68 ?? ?? ?? ?? 66 89 5e 04 e8 ?? ?? ?? ?? c7 84 24 b4 00 00 00 ff ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "-u %USERNAME% -p %PASSWORD%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Deminnix_A_2147683517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deminnix.A"
        threat_id = "2147683517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deminnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 18 00 00 00 8d 84 24 74 01 00 00 e8 ?? ?? ?? ?? 83 f8 ff 75 6b 68 04 31 44 00 bb 1d 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "tabpage\": )([^\"]*?)(,)" wide //weight: 1
        $x_1_3 = "override_url\", \"{URL}\");" ascii //weight: 1
        $x_1_4 = "621B613C303F4cac94A15E59887752F0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


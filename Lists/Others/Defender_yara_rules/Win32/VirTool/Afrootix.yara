rule VirTool_Win32_Afrootix_2147608054_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Afrootix"
        threat_id = "2147608054"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Afrootix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 3d a0 57 41 00 00 74 2b 68 18 37 41 00 a1 a0 57 41 00 50 e8 93 0f ff ff 8b f0 89 f3 85 f6 74 13 6a 00 b9 a4 57 41 00 ba f0 2e 41 00 8b c6 e8 64 b5 ff ff}  //weight: 10, accuracy: High
        $x_1_2 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_3 = "netstat.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Afrootix_2147608054_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Afrootix"
        threat_id = "2147608054"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Afrootix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 81 c4 04 f0 ff ff 50 81 c4 84 fc ff ff 53 56 57 8b f1 8d 7d d0 a5 a5 a5 a5 89 55 fc 8b 5d 08 8b 45 d8 48 74 1e 83 e8 03 0f 84 37 02 00 00 48 0f 84 61 02 00 00 83 e8 04 0f 84 56 03 00 00 e9 a7 03 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "TTunnel58.54.51.223" ascii //weight: 1
        $x_1_3 = "TTunnelxiaoyu0917.vicp.net" ascii //weight: 1
        $x_1_4 = "TTunnelphotoangel111.6600.org" ascii //weight: 1
        $x_1_5 = "TTunnelxiaozi.33222.org" ascii //weight: 1
        $x_1_6 = "TTunnelcshow.3322.org" ascii //weight: 1
        $x_1_7 = "TTunneljxaytql.vicp.cc" ascii //weight: 1
        $x_1_8 = "1.2.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Afrootix_C_2147616856_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Afrootix.gen!C"
        threat_id = "2147616856"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Afrootix"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 89 1e [0-7] 8b d6 83 c2 05 8b c3 e8 ?? 00 00 00 8b d6 83 c2 04 88 02 c6 03 e9 8b c3 40 89 38 [0-7] 8d 45 f4 50 8b 45 f4 50 6a 05 53 e8 ?? ?? ff ff 83 c6 05 8b 45 fc 89 30 33 c0 5a 59 59 64 89 10 eb 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Afrootix_B_2147616857_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Afrootix.gen!B"
        threat_id = "2147616857"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Afrootix"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 f0 89 03 [0-2] 8b fb 8b d7 83 c2 05 8b 45 f0 e8 ?? 00 00 00 83 c7 04 88 07 8b 45 f0 c6 00 e9 8b 45 f0 40 89 30 [0-2] 8d 45 f4 50 8b 45 f4 50 6a 05 8b 45 f0 50 e8 ?? ?? ff ff 83 c3 05 8b 45 fc 89 18 33 c0 5a 59 59 64 89 10 eb 11}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d0 8b c6 e8 ?? ?? ff ff 89 45 f4 6a 0c 6a 00 8d 4d f0 ba ?? ?? 14 13 8b c6 e8 ?? ?? ff ff 85 c0 74 0f 50 e8 ?? ?? ff ff b3 01 6a 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


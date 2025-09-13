rule Trojan_Win32_Phorpiex_DSK_2147741061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.DSK!MTB"
        threat_id = "2147741061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qemu" ascii //weight: 1
        $x_1_2 = "virtual" ascii //weight: 1
        $x_1_3 = "vmware" ascii //weight: 1
        $x_1_4 = {99 b9 1a 00 00 00 f7 f9 83 c2 61 8b 45 f8 03 45 fc 88 10 eb d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_DHE_2147744383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.DHE!MTB"
        threat_id = "2147744383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 8b 3c 8d ?? ?? ?? ?? 03 c7 25 ff 00 00 00 8a 14 85 ?? ?? ?? ?? 89 3c 85 ?? ?? ?? ?? 0f b6 d2 89 14 8d ?? ?? ?? ?? 8b 3c 85 ?? ?? ?? ?? 03 fa 81 e7 ff 00 00 00 0f b6 14 bd ?? ?? ?? ?? 30 14 2e 83 ee 01 79 b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_AR_2147745613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.AR!MTB"
        threat_id = "2147745613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d8 8b 45 08 03 45 fc 88 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_MLN_2147751746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.MLN!MTB"
        threat_id = "2147751746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 34 03 e8 ?? ?? ?? ?? 30 06 83 6d ?? 01 39 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_MER_2147752131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.MER!MTB"
        threat_id = "2147752131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8d 3c 03 e8 ?? ?? ?? ?? 30 07 83 6d ?? 01 39 75 ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_KA_2147762990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.KA!MTB"
        threat_id = "2147762990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tsrv1.ws" ascii //weight: 1
        $x_1_2 = "tsrv2.top" ascii //weight: 1
        $x_1_3 = "C:\\DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_SBR_2147763441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.SBR!MSR"
        threat_id = "2147763441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c start __ & __\\DriveMgr.exe & exit" wide //weight: 1
        $x_1_2 = "FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" wide //weight: 1
        $x_1_3 = "%userprofile%" wide //weight: 1
        $x_1_4 = "worm.top" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_SBR_2147763441_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.SBR!MSR"
        threat_id = "2147763441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://tsrv1.ws" ascii //weight: 5
        $x_1_2 = "DisableScanOnRealtimeEnable" wide //weight: 1
        $x_1_3 = "DisableOnAccessProtection" wide //weight: 1
        $x_1_4 = "DisableBehaviorMonitoring" wide //weight: 1
        $x_1_5 = "FirewallDisableNotify" wide //weight: 1
        $x_1_6 = "AntiVirusOverride" wide //weight: 1
        $x_1_7 = "FirewallOverride" wide //weight: 1
        $x_1_8 = "/c start __ & __\\DriveMgr.exe & exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Phorpiex_PX_2147767290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.PX!MTB"
        threat_id = "2147767290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetStartupInfoA" ascii //weight: 1
        $x_1_2 = "ShellExecuteW" ascii //weight: 1
        $x_1_3 = "wt4wtw4tw4tw4tw4t" wide //weight: 1
        $x_1_4 = "http://trik.ws/p.jpg" wide //weight: 1
        $x_1_5 = "http://trik.ws/pc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_RR_2147773577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.RR!MTB"
        threat_id = "2147773577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\zuhejatikihuzizoti94 vutek-wotamu\\jaberucere-lujawo.pdb" ascii //weight: 1
        $x_1_2 = "honey.pdb" ascii //weight: 1
        $x_1_3 = "GetMonitorInfoA" ascii //weight: 1
        $x_1_4 = "WinHttpGetDefaultProxyConfiguration" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_SM_2147781244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.SM!MSR"
        threat_id = "2147781244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bitcoincash:qrzu3lahc7thkstxdsjamym2sak78j6mpy23fk3mxj" ascii //weight: 1
        $x_1_2 = "http://185.215.113.93/" ascii //weight: 1
        $x_1_3 = "http://feedmefile.top/" ascii //weight: 1
        $x_1_4 = "http://gotsomefile.top/" ascii //weight: 1
        $x_1_5 = "http://gimmefile.top/" ascii //weight: 1
        $x_1_6 = "%systemdrive%" wide //weight: 1
        $x_1_7 = "%userprofile%" wide //weight: 1
        $x_1_8 = "%temp%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_A_2147787041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.A!MTB"
        threat_id = "2147787041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 30 75 00 00 f7 f9 81 c2 10 27 00 00 52 e8 ?? ?? ?? ?? 99 b9 30 75 00 00 f7 f9 81 c2 10 27 00 00 52 8d 95 f0 fb ff ff 52}  //weight: 1, accuracy: Low
        $x_1_2 = {99 b9 60 ea 00 00 f7 f9 6b d2 ?? 81 c2 10 27 00 00 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "http://185.215.113.93" ascii //weight: 1
        $x_1_4 = "4wgw4gw4h" ascii //weight: 1
        $x_1_5 = "appdata" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_JK_2147794883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.JK"
        threat_id = "2147794883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e5 a0 f3 e2 a1 c1 9d b1 a1 c1 9d b1 a1 c1 9d b1 32 8f 05 b1 a3 c1 9d b1 ba 5c 03 b1 8d c1 9d b1 ba 5c 36 b1 9c c1 9d b1 ba 5c 37 b1 2d c1 9d b1 a8 b9 0e b1 80 c1 9d b1 a1 c1 9c b1 8e c0 9d b1 ba 5c 32 b1 89 c1 9d b1 ba 5c 07 b1 a0 c1 9d b1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_V_2147796172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.V!MTB"
        threat_id = "2147796172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bnb1yzw7m55vrhqmmw2e0xpven8q49u8m63prv3hhz" ascii //weight: 1
        $x_1_2 = "band1ecl9c2w2dtxx70pewvsl6le3sd8srrlg36vthx" ascii //weight: 1
        $x_1_3 = "bc1q4eym03072yk0zahdm9jym28vk0dxwyvs57sr6g" ascii //weight: 1
        $x_1_4 = "cosmos" wide //weight: 1
        $x_1_5 = "bitcoincash:" wide //weight: 1
        $x_1_6 = "VolDriver.exe" wide //weight: 1
        $x_1_7 = "nodesinfo.dat" wide //weight: 1
        $x_1_8 = "cmdinfo.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_SIB_2147797097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.SIB!MTB"
        threat_id = "2147797097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "http://gotsomefile.top/" ascii //weight: 10
        $x_10_2 = "http://feedmefile.top/" ascii //weight: 10
        $x_10_3 = "http://gimmefile.top/" ascii //weight: 10
        $x_10_4 = "http://tsrv3.ru/" ascii //weight: 10
        $x_3_5 = "%ls:Zone.Identifier" wide //weight: 3
        $x_3_6 = {8d 55 f4 52 e8 ?? ?? ?? ?? 83 c4 04 39 45 f0 73 1d 8b 45 f0 0f be 4c 05 f4 8b 55 08 03 55 fc 0f be 02 33 c1 8b 4d 08 03 4d fc 88 01 eb c9}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_3_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Phorpiex_MA_2147809193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.MA!MTB"
        threat_id = "2147809193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 2c f4 ff ff ?? ?? ?? ?? 8b 85 f0 fd ff ff 89 85 28 f4 ff ff 8b 8d 28 f4 ff ff 66 8b 11 66 89 95 26 f4 ff ff 8b 85 2c f4 ff ff 66 3b 10 75 4b 66 83 bd 26 f4 ff ff 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = "AntiVirusDisableNotify" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_4 = "/c start .\\%s & start .\\%s\\VolDriver.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_MA_2147809193_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.MA!MTB"
        threat_id = "2147809193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {ba 05 00 00 00 66 89 55 d0 8d 45 ec 50 8d 4d a0 51 6a 00 6a 00 6a 20 6a 00 6a 00 6a 00 8b 55 08 52 6a 00 ff 15 2c 00 41 00}  //weight: 6, accuracy: High
        $x_1_2 = "NewRemoteHost" ascii //weight: 1
        $x_1_3 = "FirewallDisableNotify" ascii //weight: 1
        $x_1_4 = "AntiSpywareOverride" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlW" ascii //weight: 1
        $x_1_6 = "UnmapViewOfFile" ascii //weight: 1
        $x_1_7 = "GetDiskFreeSpaceExW" ascii //weight: 1
        $x_1_8 = "SetClipboardData" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_N_2147821698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.N!MTB"
        threat_id = "2147821698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Host Process for" wide //weight: 1
        $x_1_2 = "Phorpiex" wide //weight: 1
        $x_1_3 = "Desktop Window Mana" wide //weight: 1
        $x_1_4 = "%s\\r33r3r3r.txt" wide //weight: 1
        $x_1_5 = "%s\\w3t3twf.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_J_2147829553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.J!MTB"
        threat_id = "2147829553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a c8 8a d0 24 f0 80 e1 fc 02 c0 c0 e1 04 0a 4f 01 02 c0 0a 07 c0 e2 06 0a 57 02 88 04 1e 88 4c 1e 01 8b 4c 24 18 88 54 1e 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_AE_2147830024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.AE!MTB"
        threat_id = "2147830024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 7d f8 33 4d fc 89 7d f8 89 4d fc 8b 55 f4 8b 45 08 8b 4d f4 8b 75 08}  //weight: 2, accuracy: High
        $x_1_2 = "185.215.113.66/twizt" ascii //weight: 1
        $x_1_3 = "/c start .\\%s & start .\\%s\\VolDriver.exe" wide //weight: 1
        $x_1_4 = "s\\%d%d.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_AF_2147830087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.AF!MTB"
        threat_id = "2147830087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "185.215.113.66/tpeinf.php" wide //weight: 3
        $x_1_2 = "3f6d636f3d63fdf6df6ddf63f6f63df" wide //weight: 1
        $x_1_3 = "w4tw4tw4y4yw4yw4t4tw4t4wywt4ww4" wide //weight: 1
        $x_1_4 = "a7ff7a7f7a7f.ke" ascii //weight: 1
        $x_1_5 = "afe6fga6egaedg8aeg6a8e6fg6af8ga" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_RC_2147832291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.RC!MTB"
        threat_id = "2147832291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 7d f8 33 4d fc 89 7d f8 89 4d fc 8b 55 f4 8b 45 08 8b 4d f4 8b 75 08 8b bc d0 18 ff ff ff 23 bc ce f8 fd ff ff 8b 94 d0 1c ff ff ff 23 94 ce fc fd ff ff 33 7d f8 33 55 fc 89 7d f8 89 55 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_BF_2147837208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.BF!MTB"
        threat_id = "2147837208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 f0 0f be 4c 05 f4 8b 55 08 03 55 fc 0f be 02 33 c1 8b 4d 08 03 4d fc 88 01 eb c9 8b 55 08 03 55 fc 0f be 02 f7 d0 8b 4d 08 03 4d fc 88 01 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_RB_2147837536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.RB!MTB"
        threat_id = "2147837536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 ff 7f 00 00 f7 f9 81 c2 e8 03 00 00 52 e8 ?? ?? ?? ?? 99 b9 ff 7f 00 00 f7 f9 [0-16] 81 c2 e8 03 00 00 52 8d [0-6] 52 68 [0-16] 50 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_RB_2147837536_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.RB!MTB"
        threat_id = "2147837536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 30 75 00 00 f7 f9 81 c2 10 27 00 00 52 e8 ?? ?? ?? ?? 99 b9 30 75 00 00 f7 f9 81 c2 10 27 00 00 52 8d ?? ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_RA_2147839148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.RA!MTB"
        threat_id = "2147839148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 ff 7f 00 00 f7 f9 81 c2 e8 03 00 00 52 e8 ?? ?? ?? ?? 99 b9 ff 7f 00 00 f7 f9 81 c2 e8 03 00 00 52 8d 95 ?? ?? ff ff 52 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_LK_2147840406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.LK!MTB"
        threat_id = "2147840406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "C:\\TEMP\\Setup_21181006182607_Failed.txt" wide //weight: 5
        $x_5_2 = {25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 77 00 69 00 6e 00 [0-9] 2e 00 74 00 78 00 74 00}  //weight: 5, accuracy: Low
        $x_5_3 = "BurnPipe.%s" wide //weight: 5
        $x_5_4 = "PayloadRef" wide //weight: 5
        $x_5_5 = "C:\\TEMP\\2890.exe" wide //weight: 5
        $x_1_6 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 38 00 35 00 2e 00 32 00 31 00 35 00 2e 00 31 00 31 00 33 00 2e 00 [0-11] 70 00 70 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 73 00 72 00 76 00 [0-3] 2e 00 77 00 73 00 2f 00 [0-7] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_8 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 6c 00 64 00 72 00 6e 00 65 00 74 00 2e 00 74 00 6f 00 70 00 2f 00 [0-15] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Phorpiex_CRTF_2147849517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.CRTF!MTB"
        threat_id = "2147849517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 68 00 00 00 66 89 95 5c f9 ff ff b8 74 00 00 00 66 89 85 5e f9 ff ff b9 74 00 00 00 66 89 8d 60 f9 ff ff ba 70 00 00 00 66 89 95 62 f9 ff ff b8 3a 00 00 00 66 89 85 64 f9 ff ff b9 2f 00 00 00 66 89 8d 66 f9 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {ba 2f 00 00 00 66 89 95 68 f9 ff ff b8 31 00 00 00 66 89 85 6a f9 ff ff b9 38 00 00 00 66 89 8d 6c f9 ff ff ba 35 00 00 00 66 89 95 6e f9 ff ff b8 2e 00 00 00 66 89 85 70 f9 ff ff b9 32 00 00 00 66 89 8d 72 f9 ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {ba 31 00 00 00 66 89 95 74 f9 ff ff b8 35 00 00 00 66 89 85 76 f9 ff ff b9 2e 00 00 00 66 89 8d 78 f9 ff ff ba 31 00 00 00 66 89 95 7a f9 ff ff b8 31 00 00 00 66 89 85 7c f9 ff ff b9 33 00 00 00 66 89 8d 7e f9 ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {ba 2e 00 00 00 66 89 95 80 f9 ff ff b8 38 00 00 00 66 89 85 82 f9 ff ff b9 34 00 00 00 66 89 8d 84 f9 ff ff ba 2f 00 00 00 66 89 95 86 f9 ff ff b8 70 00 00 00 66 89 85 88 f9 ff ff b9 70 00 00 00 66 89 8d 8a f9 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_NP_2147893667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.NP!MTB"
        threat_id = "2147893667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d1 e8 89 45 f0 0f b6 4d ?? 85 c9 74 0c 8b 55 f0 81 f2 ?? ?? ?? ?? 89 55 f0 eb c4 8b 45 ?? 33 45 f0 89 45 ?? eb 84}  //weight: 5, accuracy: Low
        $x_1_2 = "://185.215.113.93/pi.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_KAA_2147899658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.KAA!MTB"
        threat_id = "2147899658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2dgd828d8g8fg8g8g" ascii //weight: 1
        $x_1_2 = "putinsucks.ua" ascii //weight: 1
        $x_1_3 = "freeukraine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_RPY_2147906015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.RPY!MTB"
        threat_id = "2147906015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "twizt.net" wide //weight: 1
        $x_1_2 = "lslut.exe" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "Windows Service" wide //weight: 1
        $x_1_5 = "Mozilla/5.0" wide //weight: 1
        $x_1_6 = "%temp%" wide //weight: 1
        $x_1_7 = "freeukraine" ascii //weight: 1
        $x_1_8 = "fuckput.in" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_APX_2147924417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.APX!MTB"
        threat_id = "2147924417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 44 1d f0 30 04 3e 8d 45 f0 50 43 e8 ?? ?? ?? ?? 59 3b d8 72 ?? f6 14 3e 57 46}  //weight: 5, accuracy: Low
        $x_3_2 = "185.215.113.66" wide //weight: 3
        $x_2_3 = {8b ec 83 ec 10 56 57 be ?? ?? ?? ?? 8d 7d f0 a5 a5 a5 a5 8b 7d 08 57 33 f6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_APE_2147924425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.APE!MTB"
        threat_id = "2147924425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d 08 03 4d fc 0f be 11 33 d0 8b 45 08 03 45 fc 88 10 eb ?? 8b 4d 08 03 4d fc 0f be 11 f7 d2 8b 45 08 03 45 fc 88 10}  //weight: 5, accuracy: Low
        $x_3_2 = "185.215.113.66" wide //weight: 3
        $x_2_3 = {83 ec 18 a1 ?? 20 40 00 89 45 ec 8b 0d ?? 20 40 00 89 4d f0 8b 15 ?? 20 40 00 89 55 f4 a1 ?? 20 40 00 89 45 f8 c7 45 ?? ?? ?? ?? ?? eb 09 8b 4d fc 83 c1 01 89 4d fc 8b 55 08 52}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_APH_2147925800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.APH!MTB"
        threat_id = "2147925800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 18 31 40 00 8d 8d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 83 c4 08 eb 15 68 60 31 40 00 8d 95}  //weight: 3, accuracy: Low
        $x_2_2 = {6a 00 6a 00 6a 00 6a 00 68 a8 31 40 00 ff 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 bd ?? ?? ?? ?? ?? 74 34 6a 00 6a 00 6a 00 6a 00 8d 85}  //weight: 2, accuracy: Low
        $x_4_3 = "91.202.233.141" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_PAQD_2147940561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.PAQD!MTB"
        threat_id = "2147940561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 e2 01 f7 da 1b d2 f7 da 88 55 ?? 8b 45 ?? d1 e8 89 45 ?? 0f b6 4d ?? 85 c9 74 0c 8b 55 ?? 81 f2 20 83 b8 ed 89 55}  //weight: 3, accuracy: Low
        $x_3_2 = {ba 2f 00 00 00 66 89 95 ?? ?? ?? ?? b8 74 00 00 00 66 89 85 ?? ?? ?? ?? b9 73 00 00 00 66 89 8d ?? ?? ?? ?? ba 72 00 00 00 66 89 95 ?? ?? ?? ?? b8 76 00 00 00 66 89 85 ?? ?? ?? ?? b9 31 00 00 00 66 89 8d 82 ?? ?? ?? ?? 2e 00 00 00 66 89 95 ?? ?? ?? ?? b8 77 00 00 00 66 89 85 ?? ?? ?? ?? b9 73 00 00 00 66 89 8d ?? ?? ?? ?? ba 2f 00 00 00}  //weight: 3, accuracy: Low
        $x_2_3 = {89 55 d8 b8 ?? ?? ?? ?? 66 89 45 e4 b9 ?? ?? ?? ?? 66 89 4d e6 ba ?? ?? ?? ?? 66 89 55 e8 b8 ?? ?? ?? ?? 66 89 45 ea b9 ?? ?? ?? ?? 66 89 4d ec ba ?? ?? ?? ?? 66 89 55 ee b8 ?? ?? ?? ?? 66 89 45 f0 b9 ?? ?? ?? ?? 66 89 4d f2 ba ?? ?? ?? ?? 66 89 55 f4 b8 ?? ?? ?? ?? 66 89 45 f6 b9 ?? ?? ?? ?? 66 89 4d f8 ba ?? ?? ?? ?? 66 89 55 fa}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Phorpiex_NIT_2147952200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorpiex.NIT!MTB"
        threat_id = "2147952200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 10 6a 04 8d 44 24 18 50 6a 04 6a 00 68 4c de 40 00 51 ff d6 8b 44 24 10 6a 04 8d 54 24 18 52 6a 04 6a 00 68 60 de 40 00 50 ff d6 8b 54 24 10 6a 04 8d 4c 24 18 51 6a 04 6a 00 68 78 de 40 00 52 ff d6 8b 4c 24 10 6a 04 8d 44 24 18 50 6a 04 6a 00 68 8c de 40 00 51 ff d6 8b 44 24 10 6a 04 8d 54 24 18 52 6a 04 6a 00 68 a0 de 40 00 50 ff d6 8b 54 24 10 6a 04 8d 4c 24 18 51 6a 04 6a 00 68 b8 de 40 00 52 ff d6 8b 4c 24 10 6a 04 8d 44 24 18 50 6a 04 6a 00 68 c8 de 40 00 51 ff d6 8b 54 24 10 52 ff d3 8d 44 24 10}  //weight: 2, accuracy: High
        $x_2_2 = {51 ff 15 1c d1 40 00 89 44 24 14 83 f8 ff 0f 84 05 02 00 00 8b 1d a8 d0 40 00 8d 94 24 d8 0c 00 00 c7 44 24 30 10 db 40 00 c7 44 24 34 1c db 40 00 c7 44 24 38 28 db 40 00 c7 44 24 3c 34 db 40 00 c7 44 24 40 4c db 40 00 c7 44 24 44 58 db 40 00 c7 44 24 48 64 db 40 00 c7 44 24 4c 70 db 40 00 c7 44 24 50 7c db 40 00 c7 44 24 54 88 db 40 00 c7 44 24 58 94 db 40 00 c7 44 24 5c a0 db 40 00 c7 44 24 18 bc 03 41 00 89 54 24 1c c7 44 24 20 ac db 40 00 c7 44 24 24 c0 db 40 00 c7 44 24 28 dc db 40 00 c7 44 24 2c f4 db 40 00 eb 06 8d 9b 00 00 00 00 8b 3d 38 d1 40 00 68 a8 da 40 00 8d 84 24 90 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "bitcoincash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


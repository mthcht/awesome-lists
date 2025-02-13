rule Worm_Win32_Silly_P2P_E_2147598342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Silly_P2P.E"
        threat_id = "2147598342"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Silly_P2P"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "123"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 100
        $x_4_2 = "\\Software\\Kazaa\\LocalContent" ascii //weight: 4
        $x_4_3 = "PathWWWRoot" ascii //weight: 4
        $x_4_4 = "<meta http-equiv=\"refresh\" content=\"1;URL=" ascii //weight: 4
        $x_4_5 = "\\KaZaa\\My Shared Folder\\" ascii //weight: 4
        $x_3_6 = ".com/foto0" ascii //weight: 3
        $x_3_7 = "C:\\Arquivos de programas\\" ascii //weight: 3
        $x_1_8 = "\\index.htm" ascii //weight: 1
        $x_1_9 = "DownloadDir" ascii //weight: 1
        $x_1_10 = "SystemDrive" ascii //weight: 1
        $x_1_11 = "\\My Downloads\\" ascii //weight: 1
        $x_1_12 = "\\Warez P2P Client\\My Shared Folder\\" ascii //weight: 1
        $x_1_13 = "\\Morpheus\\Downloads\\" ascii //weight: 1
        $x_1_14 = "\\KMD\\My Shared Folder\\" ascii //weight: 1
        $x_1_15 = "\\BearShare\\Shared\\" ascii //weight: 1
        $x_1_16 = "\\KaZaa Lite\\My Shared Folder\\" ascii //weight: 1
        $x_1_17 = "\\Grokster\\My Shared Folder\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 4 of ($x_4_*) and 7 of ($x_1_*))) or
            ((1 of ($x_100_*) and 4 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 4 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Silly_P2P_F_2147621246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Silly_P2P.F"
        threat_id = "2147621246"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Silly_P2P"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 83 65 fc 00 83 65 fc 00 eb 07 8b 45 fc 40 89 45 fc ff 75 08 ff 15 0c 00 41 00 39 45 fc 7d 16 8b 45 08 03 45 fc 0f be 00 33 45 0c 8b 4d 08 03 4d fc 88 01 eb d5 8b 45 08 c9 c3}  //weight: 1, accuracy: High
        $x_1_2 = "\\Software\\eMule" ascii //weight: 1
        $x_1_3 = "\\SOFTWARE\\Altnet" ascii //weight: 1
        $x_1_4 = {55 54 20 32 30 30 33 20 4b 65 79 47 65 6e 2e 65 78 65 [0-4] 48 61 6c 66 2d 4c 69 66 65 20 32 20 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Silly_P2P_G_2147622768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Silly_P2P.G"
        threat_id = "2147622768"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Silly_P2P"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d [0-32] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_2 = {69 63 6f 6e 3d 25 [0-16] 25 5c 73 79 73 74 65 6d 33 32 5c 53 48 45 4c 4c 33 32 2e 64 6c 6c 2c}  //weight: 10, accuracy: Low
        $x_10_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 10
        $x_10_4 = "\\autorun.inf" ascii //weight: 10
        $x_1_5 = "Software\\BearShare\\General" ascii //weight: 1
        $x_1_6 = "Software\\iMesh\\General" ascii //weight: 1
        $x_1_7 = "Software\\Shareaza\\" ascii //weight: 1
        $x_1_8 = "Software\\Kazaa\\" ascii //weight: 1
        $x_1_9 = "Software\\DC++" ascii //weight: 1
        $x_1_10 = "Software\\eMule" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Silly_P2P_K_2147653774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Silly_P2P.K"
        threat_id = "2147653774"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Silly_P2P"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|Windows Live Messenger|" ascii //weight: 1
        $x_2_2 = "PassFirefox" ascii //weight: 2
        $x_2_3 = "\\Downloads\\eMule\\Incoming\\" ascii //weight: 2
        $x_2_4 = "\\kazaa lite k++\\my shared folder\\" ascii //weight: 2
        $x_4_5 = "StartSpread" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Silly_P2P_A_2147681421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Silly_P2P.gen!A"
        threat_id = "2147681421"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Silly_P2P"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 17 c7 85 ?? ?? ff ff 01 00 00 00 68 98 3a 00 00 ff 15 ?? ?? ?? 00 eb 02 eb 02 eb ?? 6a 07 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? 00 83 bd ?? ?? ff ff 00 74 05}  //weight: 2, accuracy: Low
        $x_2_2 = {83 7d 0c 07 75 3b 6a 3f 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 e8 ?? ?? 00 00 83 c4 0c ff 75 10 8d 85 ?? ?? ff ff 50 68 ?? ?? ?? ?? 68 ff 01 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {99 6a 0a 59 f7 f9 52}  //weight: 1, accuracy: High
        $x_1_4 = "website=1" ascii //weight: 1
        $x_1_5 = "kazaa\\my shared folder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


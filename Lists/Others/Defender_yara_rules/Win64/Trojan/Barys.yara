rule Trojan_Win64_Barys_ABS_2147851292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.ABS!MTB"
        threat_id = "2147851292"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 eb c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 ?? 0f b6 c3 2a c2 04 37 41 30 00 ff c3 4d 8d 40 01 83 fb}  //weight: 5, accuracy: Low
        $x_5_2 = {49 8b d1 49 8b ca e8 ?? ?? ?? ?? b9 b8 0b 00 00 ff 15 ?? ?? ?? ?? 33 c9 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_RE_2147852055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.RE!MTB"
        threat_id = "2147852055"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7JeJsZJ4UcN5JhnbenB37sHa5G3vcMNY" ascii //weight: 1
        $x_1_2 = "7yUCsWZa2hTDfP77E" ascii //weight: 1
        $x_1_3 = "765WjC25M4kbc24dxdCYJhxxip0878dK" ascii //weight: 1
        $x_1_4 = "d\\Desktop\\highbit\\x64\\Release\\direct_bit.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_GME_2147890054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.GME!MTB"
        threat_id = "2147890054"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b1 9f 33 7e 9c 87 18 89 80 ?? ?? ?? ?? 0a 82}  //weight: 10, accuracy: Low
        $x_1_2 = "7e7fekaQ" ascii //weight: 1
        $x_1_3 = "rF5uXRx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_RF_2147894980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.RF!MTB"
        threat_id = "2147894980"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gWkcbSKjrShdEmYN" ascii //weight: 1
        $x_1_2 = "Kp110MPIQdAJR5qq" ascii //weight: 1
        $x_1_3 = "4dd1b23e-fb8d-49be-a20e-49aea69eb782" ascii //weight: 1
        $x_1_4 = "P0N*R$T" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_NA_2147901238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.NA!MTB"
        threat_id = "2147901238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 1d 3b b9 01 00 48 8d 3d ?? ?? ?? ?? eb 12 48 8b 03 48 85 c0 74 06 ff 15 c4 50 00 00 48 83 c3 08}  //weight: 5, accuracy: Low
        $x_1_2 = "gzweox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_PADD_2147901257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.PADD!MTB"
        threat_id = "2147901257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 34 77 34 77 34 77 34 77 45 0f b7 c2 48 8b c8 42 8b 14 83 49 03 d7 0f b6 02 85 c0 0f 84 88}  //weight: 1, accuracy: High
        $x_1_2 = "HellsGate.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_NBS_2147901419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.NBS!MTB"
        threat_id = "2147901419"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Injecting : Bone Neck First" ascii //weight: 1
        $x_1_2 = "Aimbot Scope : Enabled" ascii //weight: 1
        $x_1_3 = "Reseting Guest Account" ascii //weight: 1
        $x_1_4 = "Injecting Bypass - Anticheat.." ascii //weight: 1
        $x_1_5 = "Bypass - Anticheat I : Injected!" ascii //weight: 1
        $x_1_6 = "Injecting Aimneck.." ascii //weight: 1
        $x_1_7 = "Npc Name: Injecting" ascii //weight: 1
        $x_1_8 = "Bypass - Antiblack : Injected!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_VI_2147901421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.VI!MTB"
        threat_id = "2147901421"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Injecting Bypass - Anticheat.." ascii //weight: 1
        $x_1_2 = "HD-Player.exe" ascii //weight: 1
        $x_1_3 = "MEmuHeadless.exe" ascii //weight: 1
        $x_1_4 = "LdVBoxHeadless.exe" ascii //weight: 1
        $x_1_5 = "Sniper Scope : Unsuccessful!" ascii //weight: 1
        $x_1_6 = "Emulator - Bypass: Applying" ascii //weight: 1
        $x_1_7 = "host=%s" ascii //weight: 1
        $x_1_8 = "port=%ld" ascii //weight: 1
        $x_1_9 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_VX_2147901422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.VX!MTB"
        threat_id = "2147901422"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HD-Player.exe" ascii //weight: 1
        $x_1_2 = "MEmuHeadless.exe" ascii //weight: 1
        $x_1_3 = "LdVBoxHeadless.exe" ascii //weight: 1
        $x_1_4 = "Internet Block: Enabled" ascii //weight: 1
        $x_1_5 = "netsh advfirewall firewall delete rule name=all program=" ascii //weight: 1
        $x_1_6 = "joeboxcontrol.exe" ascii //weight: 1
        $x_1_7 = "Fiddler.exe" ascii //weight: 1
        $x_1_8 = "joeboxserver.exe" ascii //weight: 1
        $x_1_9 = "ImmunityDebugger.exe" ascii //weight: 1
        $x_1_10 = "Wireshark.exe" ascii //weight: 1
        $x_1_11 = "ollydbg.exe" ascii //weight: 1
        $x_1_12 = "ProcessHacker.exe" ascii //weight: 1
        $x_1_13 = "Dump-Fixer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_NB_2147901865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.NB!MTB"
        threat_id = "2147901865"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 07 09 c0 74 4a 8b 5f 04 48 8d 8c 30 ?? ?? ?? ?? 48 01 f3 48 83 c7 08 ff 15 60 0b 00 00 48 95}  //weight: 3, accuracy: Low
        $x_1_2 = {48 89 f9 48 89 fa ff c8 f2 ae 48 89 e9 ff 15 52 0b 00 00 48 09 c0 74 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_NB_2147901865_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.NB!MTB"
        threat_id = "2147901865"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tayfa Proxy" ascii //weight: 1
        $x_1_2 = "PARKOURX" ascii //weight: 1
        $x_1_3 = "Baglanti hatasi!" ascii //weight: 1
        $x_1_4 = "Done HTTPS!" ascii //weight: 1
        $x_1_5 = "Tayfa Proxy by Kayip and Throxy" ascii //weight: 1
        $x_1_6 = "You can now connect to Growtopia" ascii //weight: 1
        $x_1_7 = "Gems to Avoid jebs!, Now Gems is" ascii //weight: 1
        $x_1_8 = "Basilan tus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_WZ_2147907973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.WZ!MTB"
        threat_id = "2147907973"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "discord.com/api/webhooks/" ascii //weight: 1
        $x_1_2 = "curl -i -H \"Accept: application/json\" -H \"Content-Type:application/json\" -X POST --data" ascii //weight: 1
        $x_1_3 = "&& timeout /t 5 >nul 2>&1" ascii //weight: 1
        $x_1_4 = "start cmd /C \"color b && title Error && echo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_RM_2147908409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.RM!MTB"
        threat_id = "2147908409"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 7c 24 70 48 89 d9 e8 f1 03 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 02 00 00 00 48 89 d9 ba 00 00 00 40 41 b8 02 00 00 00 45 31 c9 ff 15 79 3e 02 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_NE_2147909350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.NE!MTB"
        threat_id = "2147909350"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 39 ca 74 0e 46 8a 54 0c 30 46 ?? 14 0f 49 ff c1}  //weight: 5, accuracy: Low
        $x_5_2 = {48 39 ca 74 0d 44 8a 04 08 45 30 04 0c 48 ff c1 eb ee}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_EC_2147909913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.EC!MTB"
        threat_id = "2147909913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "no-stem-" ascii //weight: 2
        $x_2_2 = "imgui_log.txt" ascii //weight: 2
        $x_2_3 = "kNoTO5iVLG" ascii //weight: 2
        $x_2_4 = "Aimbot v6 : Injected!" ascii //weight: 2
        $x_2_5 = "SAKIB CHEAT.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_RD_2147915509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.RD!MTB"
        threat_id = "2147915509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\soare\\Desktop\\Xbest Prime xx\\Xbest Prime xx\\examples\\Exe\\Xbest Prime.pdb" ascii //weight: 1
        $x_1_2 = "netsh advfirewall firewall delete rule name=all program=\"%ProgramFiles%\\BlueStacks\\HD-Player.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_GPA_2147918624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.GPA!MTB"
        threat_id = "2147918624"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "cipher-0.3.0\\src\\stream.rs" ascii //weight: 4
        $x_3_2 = "src\\misc\\discord.rs" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_TTV_2147931446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.TTV!MTB"
        threat_id = "2147931446"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 01 c2 81 c2 00 00 00 8d 42 33 14 30 42 89 94 34 ?? ?? ?? ?? 49 83 c6 04 49 83 fe 43 76 d3 8a 40 44 34 6d 48 8d bc 24 ?? ?? ?? ?? 88 47 44 6a 45 41 5e 4c 89 f1 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_ARA_2147948754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.ARA!MTB"
        threat_id = "2147948754"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c1 c1 e8 1e 33 c1 69 d0 65 89 07 6c 41 03 d0 42 89 54 83 04 8b ca 49 ff c0 49 81 f8 70 02 00 00 72 dd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_DDS_2147948976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.DDS!MTB"
        threat_id = "2147948976"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 64 48 8b 4d 48 0f b6 04 01 83 f0 5e 8b 4d 64 ?? 8b 55 48 88 04 0a eb}  //weight: 5, accuracy: Low
        $x_4_2 = {8b 45 64 ff c0 89 45 64}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_PAHO_2147949995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.PAHO!MTB"
        threat_id = "2147949995"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 ff c6 88 17 48 ff c7 8a 16 01 db 75 ?? 8b 1e 48 83 ee fc 11 db 8a 16 72 e6}  //weight: 2, accuracy: Low
        $x_3_2 = {48 8d be 00 60 01 00 8b 07 09 c0 74 ?? 8b 5f 04 48 8d 8c 30 b4 83 01 00 48 01 f3 48 83 c7 08 ff 15 ?? ?? ?? ?? 48 95 8a 07 48 ff c7 08 c0 74}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Barys_GXY_2147951312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Barys.GXY!MTB"
        threat_id = "2147951312"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 57 18 d0 ff 0b 4c 34 09 d2 e3 09 f8 d8 06 32 11}  //weight: 5, accuracy: High
        $x_5_2 = {30 6b 2e 00 e9 65 bf ?? ?? ?? ?? 10 f2 f2 00 14 32 2d ?? ?? ?? ?? 3e 00 e6 81 0f a9 6c ee 94 1d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


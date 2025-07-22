rule Trojan_Win64_Zusy_RB_2147840019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RB!MTB"
        threat_id = "2147840019"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8b c9 66 90 8d 41 a5 30 04 0a 48 ff c1 48 83 f9 0c 72 f1 c6 42 0d 00}  //weight: 1, accuracy: High
        $x_1_2 = "poofer_update.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_RK_2147842776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RK!MTB"
        threat_id = "2147842776"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "avtest\\projects\\RedTeam\\c2implant\\implant" ascii //weight: 1
        $x_1_2 = "yarttdn.de" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\tnalpmi.exe" ascii //weight: 1
        $x_1_4 = "A Zee Too Im-Plant" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_BV_2147845936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.BV!MTB"
        threat_id = "2147845936"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Popsegkfwoieswgjiwoehgioerj" ascii //weight: 2
        $x_2_2 = "Vrheroigjw4oiughjser" ascii //weight: 2
        $x_2_3 = "CreateMutexW" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_BW_2147845937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.BW!MTB"
        threat_id = "2147845937"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "UisgoseioijegioweAosjeghioesjh" ascii //weight: 2
        $x_2_2 = "YioprgoipwrQoogjisejgies" ascii //weight: 2
        $x_2_3 = "kflgskrgopseopihsejhij" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EK_2147853092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EK!MTB"
        threat_id = "2147853092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Game Repack Install" wide //weight: 1
        $x_1_2 = {2e 74 68 65 6d 69 64 61 00 c0 76 00 00 60 15 00 00 00 00 00 00 b2 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_RG_2147889353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RG!MTB"
        threat_id = "2147889353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c7 48 89 5c 24 30 c7 44 24 28 e8 03 00 00 c7 44 24 20 02 00 00 00 48 89 c1 ba 0a 04 00 00 45 31 c0 45 31 c9 ff 15 73 c2 45 00 48 81 7d e0 0a 04 00 00 75 2b c7 85 20 02 00 00 00 00 00 00 48 8d 95 20 02 00 00 48 89 f9 ff 15 d7 c1 45 00}  //weight: 1, accuracy: High
        $x_1_2 = "E:\\Projects\\multiloader\\bin\\Release\\inj.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_YAB_2147896915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.YAB!MTB"
        threat_id = "2147896915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 c1 e0 02 48 2b c8 49 0f af cf 8a 44 0d ?? 43 32 04 0a 41 88 01 49 ff c1 41}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_YAB_2147896915_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.YAB!MTB"
        threat_id = "2147896915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c2 41 8b d1 c1 ea 10 89 05 7f 04 04 00 49 63 88 ?? ?? ?? ?? 49 8b 80 ?? ?? ?? ?? 88 14 01 41 8b d1 48 8b 05 5c 03 04 00 c1 ea 08 ff 80 88 00 00 00 48 8b 05 4c 03 04 00 48 63 88 88 00 00 00 48 8b 80 b0 00 00 00 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AMBC_2147898998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AMBC!MTB"
        threat_id = "2147898998"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 41 58 30 44 0d a8 48 ff c1 48 83 f9 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AUZ_2147899195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AUZ!MTB"
        threat_id = "2147899195"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 15 66 af 03 00 48 8b cb 48 89 05 14 30 14 00 ff 15 ?? ?? ?? ?? 48 8d 15 67 af 03 00 48 8b cb 48 89 05 05 30 14 00 ff 15 ?? ?? ?? ?? 48 8d 15 70 af 03 00 48 8b cb 48 89 05 f6 2f 14 00 ff 15 ?? ?? ?? ?? 48 8d 15 71 af 03 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EM_2147901026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EM!MTB"
        threat_id = "2147901026"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 8b 40 04 41 03 c2 48 98 48 8d 0c 40 41 8b 00 41 03 c3 49 83 c0 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EM_2147901026_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EM!MTB"
        threat_id = "2147901026"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Game Repack Install" wide //weight: 1
        $x_1_2 = {2e 74 68 65 6d 69 64 61 00 a0 73 00 00 60 15 00 00 00 00 00 00 b2 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EM_2147901026_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EM!MTB"
        threat_id = "2147901026"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jPa3hpzBvq" ascii //weight: 1
        $x_1_2 = "Discord DM : _encrypt3d." ascii //weight: 1
        $x_1_3 = "\\StarHighSrcFixV3\\Blue loader\\Blue loader" ascii //weight: 1
        $x_1_4 = "Star_High" ascii //weight: 1
        $x_1_5 = "p2j1rac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EM_2147901026_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EM!MTB"
        threat_id = "2147901026"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I Follow You.dll" ascii //weight: 1
        $x_1_2 = "I_Follow_You_aujdaw" ascii //weight: 1
        $x_1_3 = "GetTempPathA" ascii //weight: 1
        $x_1_4 = "CopyFileA" ascii //weight: 1
        $x_1_5 = "WinExec" ascii //weight: 1
        $x_1_6 = "WinHttpReceiveResponse" ascii //weight: 1
        $x_1_7 = "ceilf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EM_2147901026_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EM!MTB"
        threat_id = "2147901026"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\Desktop\\TheDLL\\x64\\Release\\TheDLL.pdb" ascii //weight: 1
        $x_1_2 = "JLI_InitArgProcessing" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileW" ascii //weight: 1
        $x_1_4 = "OpenMutexA" ascii //weight: 1
        $x_1_5 = "CreateThread" ascii //weight: 1
        $x_1_6 = "GetTempPathW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EM_2147901026_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EM!MTB"
        threat_id = "2147901026"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EasyAntiCheat.sys" ascii //weight: 1
        $x_1_2 = "EacExploit.pdb" ascii //weight: 1
        $x_1_3 = "\\Device\\injdrv" ascii //weight: 1
        $x_1_4 = "\\DosDevices\\injdrv" ascii //weight: 1
        $x_1_5 = "\\Driver\\injdrv" ascii //weight: 1
        $x_1_6 = "PsLoadedModuleList" ascii //weight: 1
        $x_1_7 = "[-] Failed to get temp path" ascii //weight: 1
        $x_1_8 = "Failed to open file for writing." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_NZA_2147901505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NZA!MTB"
        threat_id = "2147901505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {e8 10 57 00 00 33 d2 48 8d 8c 24 ?? ?? ?? ?? e8 69 1c 00 00 48 8b 8c 24 ?? ?? ?? ?? 48 8d 84 24 ?? ?? ?? ?? 48 89 41 40 48 8d 8c 24 50 01}  //weight: 3, accuracy: Low
        $x_3_2 = {eb 10 33 db 89 9c 24 ?? ?? ?? ?? 48 8d 35 a2 37 fd ff bf ?? ?? ?? ?? 8b cf e8 16 36}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_NZ_2147901866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NZ!MTB"
        threat_id = "2147901866"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hus Loader.pdb" ascii //weight: 1
        $x_1_2 = "Key doesnt exist !" ascii //weight: 1
        $x_1_3 = "dsc.gg/rive" ascii //weight: 1
        $x_1_4 = "HusClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_NZ_2147901866_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NZ!MTB"
        threat_id = "2147901866"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start cmd /C" ascii //weight: 1
        $x_1_2 = "CreateRemoteThread" ascii //weight: 1
        $x_1_3 = "ReadProcessMemory" ascii //weight: 1
        $x_1_4 = "VeriSignMPKI-2-3950" ascii //weight: 1
        $x_1_5 = "OR_1P4RP41" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_NZ_2147901866_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NZ!MTB"
        threat_id = "2147901866"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HiveNightmare.pdb" ascii //weight: 2
        $x_2_2 = "list snapshots with vssadmin list shadows" ascii //weight: 2
        $x_2_3 = "permission issue rather than vulnerability issue, make sure you're running from a folder where you can write to" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_RX_2147903573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RX!MTB"
        threat_id = "2147903573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 ca 49 8b c0 80 e1 07 c0 e1 03 48 d3 e8 42 30 04 0a 48 ff c2 48 81 fa 0b 27 00 00 72 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_GZZ_2147905373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GZZ!MTB"
        threat_id = "2147905373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 ff c0 48 31 d0 48 c7 c2 ?? ?? ?? ?? 48 31 c0 48 89 05 ?? ?? ?? ?? 4c 01 35 ?? ?? ?? ?? 48 89 f8 50 8f 05 ?? ?? ?? ?? 48 83 f0 ?? 48 31 d0 4c 89 e0 50 8f 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_GZZ_2147905373_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GZZ!MTB"
        threat_id = "2147905373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im ProcessHacker.exe" ascii //weight: 1
        $x_1_2 = "taskkill /f /im FiddlerEverywhere.exe" ascii //weight: 1
        $x_1_3 = "taskkill /f /im OllyDbg.exe" ascii //weight: 1
        $x_1_4 = "taskkill /f /im Ida64.exe" ascii //weight: 1
        $x_1_5 = "\\\\.\\kprocesshacker" ascii //weight: 1
        $x_1_6 = "cdn.discordapp.com/attachments" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EC_2147905565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EC!MTB"
        threat_id = "2147905565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 d0 48 c1 e8 02 48 31 d0 48 89 c2 48 c1 ea 15 48 31 c2 48 89 d0 48 c1 e8 16 48 31 d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EC_2147905565_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EC!MTB"
        threat_id = "2147905565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Balling!" ascii //weight: 2
        $x_2_2 = "79.174.92.22" ascii //weight: 2
        $x_2_3 = "Fatal error in host name resolving" ascii //weight: 2
        $x_1_4 = {48 89 44 24 30 48 c7 44 24 48 87 69 00 00 48 c7 44 24 40 84 03 00 00 b9 02 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EC_2147905565_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EC!MTB"
        threat_id = "2147905565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0AfQRP1dht4aRQo31fjQO7C3MuNHwlzNOgx1ZAg==" ascii //weight: 1
        $x_1_2 = "WVY3KZnpiFVzltHbFlr5U2Z30T2llQB1ZKkUGcJVQFxtNW2NL1R3ppZZhpWDSlJhDFF1cFaVxjWVkd3JaWYH7Xw==" ascii //weight: 1
        $x_1_3 = "VWhB9a0JQyMHY1DeWJT6eTR1NcBMueBy0EEFnYwLGD8koFT8ZAMzYTXLmwtkBBZ2EW3M/7JBU/GcjM2rEy4HZLQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EC_2147905565_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EC!MTB"
        threat_id = "2147905565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Desactivado Internet!" ascii //weight: 1
        $x_1_2 = "Stream Mode  DESACTIVADO" ascii //weight: 1
        $x_1_3 = "netsh advfirewall firewall delete rule name" ascii //weight: 1
        $x_1_4 = "NOSKILL RAFA.pdb" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_6 = "TrackMouseEvent" ascii //weight: 1
        $x_1_7 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_8 = "CreateRemoteThread" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EC_2147905565_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EC!MTB"
        threat_id = "2147905565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe-Command" ascii //weight: 1
        $x_1_2 = "$tasks = Get-ScheduledTask | Where-Object {" ascii //weight: 1
        $x_1_3 = "foreach ($task in $tasks) {" ascii //weight: 1
        $x_1_4 = "Clear-RecycleBin -Force -ErrorAction SilentlyContinueC:\\Users\\Public" ascii //weight: 1
        $x_1_5 = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartupUSERPROFILEFailed to get USERPROFILE" ascii //weight: 1
        $x_1_6 = "$buffer[$count] = [byte]($tempFiles[$i])" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_NC_2147908386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NC!MTB"
        threat_id = "2147908386"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "powershell -NoProfile -ExecutionPolicy bypass -windowstyle hidden -Command" ascii //weight: 5
        $x_5_2 = "-NoProfile -windowstyle hidden -ExecutionPolicy bypass -Command " ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_RM_2147908400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RM!MTB"
        threat_id = "2147908400"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NeekroAgain\\Desktop\\esp + aim meu ultimo\\esp final testar coisas - Copia - Copia - Copia - Copia\\Valorant-External-main\\x64\\Release" ascii //weight: 1
        $x_1_2 = "rasfdtyasdas.pdb" ascii //weight: 1
        $x_1_3 = "sdfgdfgfd.pdb" ascii //weight: 1
        $x_1_4 = "iasuidosdf.pdb" ascii //weight: 1
        $x_1_5 = "im MESTEResp final testar coisas - Copia - Copia - Copia - CopiaValorant - External - mainValorantOptimusPrinceps.ttf" ascii //weight: 1
        $x_1_6 = "\\temple.rar" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Zusy_AJJ_2147910064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AJJ!MTB"
        threat_id = "2147910064"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 0f 1f 40 ?? 8d 48 58 41 30 0c 00 48 ff c0 48 83 f8 0b 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 0f 1f 84 00 ?? ?? ?? ?? 8d 50 58 30 14 08 48 ff c0 48 83 f8 43 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AMAA_2147912509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AMAA!MTB"
        threat_id = "2147912509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 f7 f9 83 c2 61 c1 e2 18 c1 fa 18 88 55 ff e8 ?? ?? ?? ?? b9 1a 00 00 00 99 f7 f9 83 c2 61 c1 e2 18 c1 fa 18 88 55 fe e8 ?? ?? ?? ?? b9 1a 00 00 00 99 f7 f9 83 c2 61 c1 e2 18 c1 fa 18 88 55 fd e8}  //weight: 2, accuracy: Low
        $x_2_2 = "v5.mrmpzjjhn3sgtq5w.pro" ascii //weight: 2
        $x_1_3 = "isapi/isapiv5.dll/v5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AR_2147913081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AR!MTB"
        threat_id = "2147913081"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 2b e0 48 8b 05 ?? ?? 00 00 48 33 c4 48 89 84 24 ?? ?? 00 00 48 8b f9 b9 ?? ?? 00 00 ff 15 ?? ?? 00 00 b9 ?? ?? 00 00 48 8d 54 24 ?? 48 8b f0 ff 15 ?? ?? 00 00 48 8b 4f 08 0f b7 09 ff 15 ?? ?? 00 00 48 8b 0f 48 8b 09 ff 15 ?? ?? 00 00 ba 02 00 00 00 8b ca 44 8d 42 0f ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {48 2b e0 48 8b 05 ?? ?? 00 00 48 33 c4 48 89 84 24 ?? ?? 00 00 4c 8b ?? 48 8b 49 08 0f b7 09 ff 15 ?? ?? 00 00 49 8b 0e 48 8b 09 ff 15 ?? ?? 00 00 b9 01 01 00 00 48 8d 54 24 ?? ff 15 ?? ?? 00 00 ba 02 00 00 00 8b ca 44 8d 42 0f ff 15}  //weight: 5, accuracy: Low
        $x_5_3 = {48 2b e0 48 8b 05 ?? ?? 00 00 48 33 c4 48 89 84 24 ?? ?? 00 00 4c 8b ?? 48 8d 54 24 ?? b9 01 01 00 00 ff 15 ?? ?? 00 00 49 8b ?? 08 0f b7 09 ff 15 ?? ?? 00 00 49 8b 0e 48 8b 09 ff 15 ?? ?? 00 00 ba 02 00 00 00 8b ca 44 8d 42 0f ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Zusy_CCIZ_2147913302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.CCIZ!MTB"
        threat_id = "2147913302"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shy Product+" ascii //weight: 1
        $x_1_2 = "Dont Crack My Program" ascii //weight: 1
        $x_1_3 = "KsDumperClient.exe" wide //weight: 1
        $x_1_4 = "x64dbg.exe" wide //weight: 1
        $x_1_5 = "cheatengine - x86_64" wide //weight: 1
        $x_1_6 = "Fiddler.exe" wide //weight: 1
        $x_1_7 = "Wireshark.exe" wide //weight: 1
        $x_1_8 = "idaq64.exe" wide //weight: 1
        $x_1_9 = "idaq.exe" wide //weight: 1
        $x_1_10 = "ollydbg.exe" wide //weight: 1
        $x_1_11 = "HxD.exe" wide //weight: 1
        $x_1_12 = "procmon.exe" wide //weight: 1
        $x_1_13 = "\\\\.\\KsDumper" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_GP_2147913590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GP!MTB"
        threat_id = "2147913590"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f 61 d4 66 41 0f db d0 66 0f 67 ca 66 0f ef c8 0f 11 09 4c 39 c1}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 da 49 89 d8 48 c1 fa 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_CCIG_2147913639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.CCIG!MTB"
        threat_id = "2147913639"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NDMzYTVjNTc2OTZlNjQ2Zjc3NzM1YzUzNzk3Mzc0NjU2ZDMzMzI1Yw==" ascii //weight: 1
        $x_1_2 = "NDg0YjQzNTUzYTVjNTM2ZjY2NzQ3NzYxNzI2NTVjNDM2YzYxNzM3MzY1NzM1YzJlNzc3Mzc2NjM1Yw==" ascii //weight: 1
        $x_1_3 = "NTM2ODY1NmM2YzVjNGY3MDY1NmU1YzYzNmY2ZDZkNjE2ZTY0" ascii //weight: 1
        $x_1_4 = "NDg0YjQzNTUzYTVjNTM2ZjY2NzQ3NzYxNzI2NTVjNDM2YzYxNzM3MzY1NzM1YzZkNzMyZDczNjU3NDc0Njk2ZTY3NzM1YzQzNzU3MjU2NjU3Mg==" ascii //weight: 1
        $x_1_5 = "NjY2ZjY0Njg2NTZjNzA2NTcy" ascii //weight: 1
        $x_1_6 = "NDg0YjQzNTUzYTVjNTM2ZjY2NzQ3NzYxNzI2NTVjNDM2YzYxNzM3MzY1NzM1YzZkNzMyZDczNjU3NDc0Njk2ZTY3NzM1Yw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_RE_2147914636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RE!MTB"
        threat_id = "2147914636"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c4 48 89 84 24 b0 02 00 00 33 c9 ff 15 dd 14 00 00 48 8b c8 ff 15 e4 14 00 00 48 8d 05 f5 15 00 00 48 89 44 24 48 48 c7 44 24 60 ?? ?? 00 00 c6 44 24 40 00 48 c7 44 24 58 00 04 00 00 b9 02 02 00 00 48 8d 94 24 10 01 00 00 ff 15 6e 13 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_ASG_2147914787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.ASG!MTB"
        threat_id = "2147914787"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 da 1b d2 83 c2 02 ff 15 ?? ?? 00 00 49 8b 4e 18 4c 8b e0 66 89 7c 24 30 0f b7 09 ff 15 ?? ?? 00 00 49 8b 0e 66 89 44 24 32 48 8b 09 ff 15 ?? ?? 00 00 44 8d 43 10 49 8b cc 48 8d 54 24 30 89 44 24 34 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8b c8 ff 15 ?? ?? 00 00 48 8d 05 ?? ?? 00 00 48 89 44 24 48 48 c7 44 24 58 87 69 00 00 c6 44 24 40 00 48 c7 44 24 50 00 04 00 00 b9 02 01 00 00 48 8d 94 24 30 01 00 00 ff 15 ?? ?? 00 00 48 8b 4c 24 48 ff 15 ?? ?? 00 00 48 8b d8 48 85 c0}  //weight: 2, accuracy: Low
        $x_2_3 = {48 8b c8 ff 15 ?? ?? 00 00 48 8d 15 ?? ?? 00 00 48 89 54 24 50 48 c7 44 24 ?? 87 69 00 00 c6 44 24 40 00 48 c7 44 24 68 00 04 00 00 48 8b ?? ?? 20 00 00 e8 ?? ?? ff ff 48 8d 15 ?? ?? ff ff 48 8b c8 ff 15 ?? ?? 00 00 b9 02 01 00 00 48 8d 55 30 ff 15 ?? ?? 00 00 48 8b 4c 24 50 ff 15 ?? ?? 00 00 48 8b d8 48 85 c0}  //weight: 2, accuracy: Low
        $x_2_4 = {48 8b c8 ff 15 ?? ?? 00 00 48 8d 05 ?? ?? 00 00 48 89 44 24 58 48 c7 44 24 70 87 69 00 00 c6 44 24 50 00 48 c7 44 24 68 00 04 00 00 b9 02 02 00 00 48 8d 55 40 ff 15 ?? ?? 00 00 48 8b 4c 24 58 ff 15 ?? ?? 00 00 48 8b d8 48 85 c0}  //weight: 2, accuracy: Low
        $x_2_5 = {48 2b e0 48 8b 05 ?? ?? 00 00 48 33 c4 48 89 84 24 70 15 00 00 48 8b f1 48 8d 54 24 40 b9 01 01 00 00 ff 15 ?? ?? 00 00 bb 02 00 00 00 8b d3 8b cb 44 8d 43 0f ff 15 ?? ?? 00 00 48 8b 4e 18 4c 8b e0 66 89 5c 24 30 0f b7 09 ff 15 ?? ?? 00 00 48 8b 0e 66 89 44 24 32 48 8b 09 ff 15 ?? ?? 00 00 89 44 24 34 44 8d 43 0e 48 8d 54 24 30 49 8b cc 33 c0 48 89 44 24 38 ff 15 ?? ?? 00 00 e8}  //weight: 2, accuracy: Low
        $x_1_6 = "Send failure" ascii //weight: 1
        $x_1_7 = "Can't connect!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Zusy_ASH_2147914994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.ASH!MTB"
        threat_id = "2147914994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c9 ff 15 ?? ?? 00 00 48 8b c8 ff 15 ?? ?? 00 00 48 8d 05 ?? ?? 00 00 48 89 44 24 48 48 c7 44 24 60 87 69 00 00 c6 44 24 40 00 48 c7 44 24 58 00 04 00 00 b9 02 02 00 00 48 8d 94 24 10 01 00 00 ff 15 ?? ?? 00 00 48 8b 4c 24 48 ff 15 ?? ?? 00 00 48 8b d8 48 85 c0 75}  //weight: 2, accuracy: Low
        $x_2_2 = {44 8d 47 0f ff 15 ?? ?? 00 00 49 8b 4e 08 48 8b d8 66 89 7c 24 40 48 89 44 24 38 0f b7 09 ff 15 ?? ?? 00 00 49 8b 0e 66 89 44 24 42 48 8b 09 ff 15 ?? ?? 00 00 89 44 24 44 44 8d 47 0e 48 8d 54 24 40 48 8b cb 33 c0 48 89 44 24 48 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AQ_2147916603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AQ!MTB"
        threat_id = "2147916603"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b7 ce ff 15 ?? ?? 00 00 66 89 44 24 2a 48 8d 46 01 0f b7 f0 41 b8 10 00 00 00 48 8d 54 24 28 48 8b cd ff 15 ?? ?? 00 00 48 8b 47 10 33 db 48 8b 08 48 85 c9 74}  //weight: 5, accuracy: Low
        $x_5_2 = {0f b7 09 ff 15 ?? ?? 00 00 48 8b 0f 66 89 44 24 ?? 48 8b 09 ff 15 ?? ?? 00 00 89 44 24 ?? 44 8d 43 0f 33 c0 8b d3 8b cb 48 89 44 24 ?? ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Zusy_HNC_2147918078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.HNC!MTB"
        threat_id = "2147918078"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {9a 73 67 65 67 66 62 65 68 62 66 6a 89 66 66 6f 68 66 6f 69 6a 63 6b 66 6b 6b 65 6d 6d 8f 71 64}  //weight: 5, accuracy: High
        $x_1_2 = {24 40 48 8d 15 ab 58 00 00 4c 89 e1 e8 69 00 00 30 34 20 2d 20 44 6f 77 6e 6c 6f 61 64 73 2e 6c 6e 6b 00 6c 6e 6b 00 00 1c 0f 01 01 03 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_HNG_2147919602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.HNG!MTB"
        threat_id = "2147919602"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 69 72 74 c7 45 ?? 75 61 6c 50 c7 45 ?? 72 6f 74 65 66 c7 45 ?? 63 74 c6 45 de 00 c7 45 ?? 43 72 65 61 c7 45 ?? 74 65 54 68 c7 45 ?? 72 65 61 64 c6 45 cc 00 c7 45 ?? 57 61 69 74 c7 45 ?? 46 6f 72 53 c7 45 ?? 69 6e 67 6c c7 45 ?? 65 4f 62 6a c7 45 ?? 65 63 74 00 ff}  //weight: 5, accuracy: Low
        $x_1_2 = {66 0f 1f 44 00 00 80 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_HNE_2147919616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.HNE!MTB"
        threat_id = "2147919616"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {48 83 ec 28 48 8d 0d ?? ?? ?? ?? ?? ?? ?? ?? 00 45 31 c0 31 d2 31 c9 e8}  //weight: 11, accuracy: Low
        $x_5_2 = {2e 6c 6e 6b 00 [0-4] 6e 6b 00 [0-8] [0-34] 00 00 ?? 14 00 00 ?? 03 03 03 [0-16] 03 03 03 03 03}  //weight: 5, accuracy: Low
        $x_5_3 = {00 00 64 65 73 6b 74 6f 70 2e 69 6e 69 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 00 ?? 14 00 00 ?? ?? ?? 02 ?? 02 ?? 02 ?? 02 ?? 02 ?? 02 ?? 02 ?? 02 11 02 ?? 02 11 02 ?? 02 ?? 02 1b 02 ?? 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_11_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Zusy_GNM_2147920028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GNM!MTB"
        threat_id = "2147920028"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 32 f4 9a b2 ab 02 3e e4 97 12 1e 25 f4 65 8e ce 8a 56 40 f7 62 0c 95 5b 61 e1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_PA_2147920701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.PA!MTB"
        threat_id = "2147920701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "desktop.ini" ascii //weight: 1
        $x_1_2 = "%s=!!! %s WILL NOT CONVERT !!!" ascii //weight: 1
        $x_4_3 = {48 83 ec 28 48 8d 0d [0-4] e8 [0-4] 45 31 c0 31 d2 31 c9 e8 [0-4] 45 31 c0 31 d2 31 c9 e8 [0-4] 45 31 c0 31 d2 31 c9 e8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_HNL_2147921835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.HNL!MTB"
        threat_id = "2147921835"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {15 6a 73 6f 6e 3a 22 69 74 65 72 61 74 6f 72 5f 73 6c 69 63 65 22}  //weight: 1, accuracy: High
        $x_2_2 = {00 6d 61 69 6e 2e 44 4c 4c 57 4d 61 69 6e 00 00 00 00 00 00 00 00 00}  //weight: 2, accuracy: High
        $x_3_3 = "json:\"client_id,omitempty" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_GZH_2147923365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GZH!MTB"
        threat_id = "2147923365"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 c1 c0 20 49 89 01 49 03 00 49 89 00 48 33 02 48 c1 c8 ?? 48 89 02 4c 8b 11 4c 03 54 24 ?? 4c 01 d0 48 89 01 49 33 01 48 c1 c8 ?? 49 89 01 49 03 00 49 89 00 48 33 02 48 d1 c0 48 89 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AMS_2147924245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AMS!MTB"
        threat_id = "2147924245"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "StealerDLL\\x64\\Release\\STEALERDLL.pdb" ascii //weight: 4
        $x_2_2 = "Monero\\wallets" ascii //weight: 2
        $x_2_3 = "Thunderbird\\Profiles" ascii //weight: 2
        $x_1_4 = "9375CFF0413111d3B88A00104B2A6676" ascii //weight: 1
        $x_1_5 = "netsh wlan show profiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AMS_2147924245_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AMS!MTB"
        threat_id = "2147924245"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "xSYEfJuEfwHwFm8ccglYY4fxpXYJTpqTqT3Rvr1W5640aab2" ascii //weight: 3
        $x_3_2 = "\\Users\\Public\\webdata\\info.dat" ascii //weight: 3
        $x_1_3 = "WebSvc ... RegisterMachine w_sUUID" ascii //weight: 1
        $x_1_4 = "/C taskkill /IM %s /F" ascii //weight: 1
        $x_1_5 = "\\Google\\Chrome\\Application\\chrome.exe\" --restore-last-session" ascii //weight: 1
        $x_1_6 = "dash.zintrack.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_ARA_2147925402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.ARA!MTB"
        threat_id = "2147925402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c1 43 32 04 10 4d 8d 40 01 2a c2 ff c2 42 88 44 05 2e 83 fa 10 7c e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_GPS_2147927297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GPS!MTB"
        threat_id = "2147927297"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 41 8b 30 04 0a 48 ff c1 48 83 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_YAC_2147927681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.YAC!MTB"
        threat_id = "2147927681"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 ff c0 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 49 0f af cf 8a 44 0d ?? 43 32 04 0a 41 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_YAD_2147928276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.YAD!MTB"
        threat_id = "2147928276"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 31 d0 58 44 30 14 0f 48 ff c1 48 89 c8}  //weight: 10, accuracy: High
        $x_1_2 = {48 09 d0 48 21 d9 48 29 c8 48 31 d1 48 89 c1 48 01 c8 48 ff c9 48 ff c3 48 ff cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_YAF_2147928543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.YAF!MTB"
        threat_id = "2147928543"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {6b c6 04 d9 9c 28 90 fe ff ff ff c6 e9 ?? ?? ?? ?? d8 f7 93}  //weight: 8, accuracy: Low
        $x_1_2 = {c8 80 00 00 48 81 ec}  //weight: 1, accuracy: High
        $x_1_3 = {9b db e3 e9 cc 6f fd ff}  //weight: 1, accuracy: High
        $x_1_4 = {ad 48 83 ee 03 35 ?? ?? ?? ?? e9 ?? ?? ?? ?? 52 02 ef 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_YAK_2147928749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.YAK!MTB"
        threat_id = "2147928749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {32 c3 48 8d 3f 48 8d 3f 02 c3 48 8d 3f 32 c3 48 8d 3f 48 8d 3f 48 8d 3f 2a c3 48 8d 3f 48 8d 3f 48 8d 3f 48 8d 3f 32 c3 48 8d 3f e9}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_YAM_2147928972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.YAM!MTB"
        threat_id = "2147928972"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c8 80 00 00 48 83 ec 60 e9}  //weight: 1, accuracy: High
        $x_10_2 = {48 8d 3f 32 c3 48 8d 3f [0-6] 02 c3 48 8d 3f 32 c3 48 8d 3f e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_ASJ_2147928987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.ASJ!MTB"
        threat_id = "2147928987"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 ?? 48 2b c8 49 0f af cf 0f b6 44 0d ?? 41 32 44 31 fc 41 88 41 ff 49 ff cc 0f}  //weight: 4, accuracy: Low
        $x_1_2 = {44 8d 4b 04 ba 00 ba 01 00 33 c9 41 b8 00 30 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_HNAE_2147929023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.HNAE!MTB"
        threat_id = "2147929023"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9b 92 e4 c1 fe e1 e6 e7 e4 e5 1a 37 4e 5c 65 66 6b 69 64 52 64 68 65 65 4d 67 70 78 2a 17 0e 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_HNS_2147929544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.HNS!MTB"
        threat_id = "2147929544"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 74 00 72 00 69 00 6e 00 67 00 46 00 69 00 6c 00 65 00 49 00 6e 00 66 00 6f 00 00 00 18 00 00 00 01 00 30 00 38 00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 44 00 00 00 01 00 56 00 61 00 72 00 46 00 69 00 6c 00 65 00 49 00 6e 00 66 00 6f 00 00 00 00 00 24 00 04 00 00 00 54 00 72 00 61 00 6e 00 73 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_2_2 = {ff ff ff 00 c3 c3 c3 c1 c7 c7 c7 ff ee ee ee fc fd fd fd ff f9 f9 f9 ff fa fa fa ff fa fa fa ff f9 f9 f9 ff f9 f9 f9 ff f9 f9 f9 ff f9 f9 f9 ff}  //weight: 2, accuracy: High
        $x_1_3 = "AutoIt3ExecuteScript" wide //weight: 1
        $x_1_4 = "AutoIt3ExecuteLine" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_HNAP_2147931545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.HNAP!MTB"
        threat_id = "2147931545"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_7_1 = "vSRxEHtGTeVQLLRoEVpjWdrWTEMSdzpVinmQFKYdwHFfidJiTRiAazgrREpzjCLbgkQWPqobgYJkIFcfKEYFPgnMyVGEdccQOuJHRyYQavjpslirWtLiXFTyzlUtAKmOMEMXRbGO" ascii //weight: 7
        $x_7_2 = "mkhViulPiqHHOEocCvVciLqRTwkgwGHcgRTBlPKkkAxFVLqMHzFlfCAAbgSacgxeBLbMyapxQwMTuurdnFbXCkXxaImi" ascii //weight: 7
        $x_2_3 = "Zeba]JGUh{DJjehFeX" ascii //weight: 2
        $x_2_4 = "Zn(X\\ck+O|jvTG}!mcU@a^" ascii //weight: 2
        $x_2_5 = "Wtd{T}hItyDgnEbcXC" ascii //weight: 2
        $x_2_6 = "dAIttvIybAxgAgNf" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_7_*) and 2 of ($x_2_*))) or
            ((2 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Zusy_ARAX_2147931743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.ARAX!MTB"
        threat_id = "2147931743"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 04 24 48 ff c0 48 89 04 24 48 8b 44 24 28 48 39 04 24 73 2e 0f b6 44 24 30 48 8b 0c 24 48 8b 54 24 08 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 0c 24 48 8b 54 24 08 48 03 d1 48 8b ca 88 01 eb bc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_GTN_2147932306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GTN!MTB"
        threat_id = "2147932306"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 34 52 2a cd fe 40 d4 b6 5e 32 01 bf ?? ?? ?? ?? 40 22 38 0c 32}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_GTP_2147932370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GTP!MTB"
        threat_id = "2147932370"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "discord.gg" ascii //weight: 1
        $x_1_2 = "Spotify Recoil Macro" ascii //weight: 1
        $x_2_3 = "discord.com/users/993976505627586591sssssssss" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_GNE_2147933011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GNE!MTB"
        threat_id = "2147933011"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f be 04 17 48 ff c2 03 c3 69 d8 01 01 00 00 8b c3 c1 e8 06 33 d8 48 3b d1}  //weight: 5, accuracy: High
        $x_5_2 = {63 66 43 91 c7 05 ?? ?? ?? ?? 02 94 5b 0a c7 05 ?? ?? ?? ?? 81 d9 9b 36 c7 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_BR_2147933853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.BR!MTB"
        threat_id = "2147933853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {80 74 24 21 ?? 80 74 24 22 ?? 80 74 24 23 ?? 80 74 24 24 ?? 80 74 24 25 ?? 80 74 24 26 ?? 80 74 24 27 ?? 66 89 4c 24 28 80 f1 ?? 80 74 24 29 ?? 34 ?? c6 44 24 20 49 88 44 24 2a 48 8d 44 24 20 88 4c 24 28}  //weight: 4, accuracy: Low
        $x_1_2 = {c1 e8 1f 03 d0 0f be c2 6b d0 ?? 0f b6 c1 ff c1 2a c2 04 ?? 41 30 40 ff 83 f9}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e8 1f 03 d0 b8 01 00 00 00 2a c2 0f be c0 6b d0 ?? 02 d1 ff c1 41 30 50 ff 83 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Zusy_SIC_2147935241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.SIC!MTB"
        threat_id = "2147935241"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 6c 24 50 48 89 d6 48 89 cf 48 8d 4d d8 48 89 fa 49 89 f0 e8 2f 37 01 00 0f b6 45 d8 48 8b 4d e8 48 8b 55 f8 44 0f b6 c0 4c 8d 0d ec e2 42 00}  //weight: 1, accuracy: High
        $x_2_2 = "PatriotSoft" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_SAI_2147935243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.SAI!MTB"
        threat_id = "2147935243"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e8 9c 41 00 00 48 8b 44 24 70 48 63 48 04 48 8d 3d ?? ?? ?? 00 48 89 7c 0c 70 48 8b 44 24 70 48 63 48 04 8d ?? ?? ?? ff ff 89 54 0c 6c 48 8b cb 48 83 7d f8 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AZY_2147935359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AZY!MTB"
        threat_id = "2147935359"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {44 8b c0 48 8d 95 ?? ?? ?? ?? 48 8d 4d 80 e8 ?? ?? ?? ?? 4c 8d 4c 24 78 41 b8 00 08 00 00 48 8d 95 ?? ?? ?? ?? 48 8b cb ff 15}  //weight: 3, accuracy: Low
        $x_1_2 = {4c 89 74 24 28 c7 44 24 20 00 00 00 80 45 33 c9 45 33 c0 48 8b d0 48 8b ce ff 15}  //weight: 1, accuracy: High
        $x_2_3 = "lognationprimecarraro.com/settings/config2.zip" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AZY_2147935359_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AZY!MTB"
        threat_id = "2147935359"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8b 15 71 0b 77 00 65 4c 8b 1c 25 58 00 00 00 4f 8b 1c d3 41 ba 30 00 00 00 4d 03 d3 4c 8b 1c 24 4c 89 51 10 48 89 69 08 4c 89 19 4c 8d 5c 24 08 c7 41 18 00 80 00 00 4c 89 59 20 49 89 4a 40}  //weight: 1, accuracy: High
        $x_3_2 = {8b 05 cf 00 77 00 65 48 8b 1c 25 58 00 00 00 48 8b 1c c3 b8 30 00 00 00 48 03 c3 48 89 84 24 c0 00 00 00 f0 83 60 38 ef 48 8b 42 18 48 8b 18 48 8b 42 20 48 8b 28 48 8b 42 28 48 8b 30 48 8b 42 30 48 8b 38 48 8b 42 58 4c 8b 20 48 8b 42 60 4c 8b 28 48 8b 42 68 4c 8b 30 48 8b 42 70 4c 8b 38}  //weight: 3, accuracy: High
        $x_2_3 = "infinitycheats\\GameHelpersLoader__NEW\\bin\\Release\\net8.0\\win-x64\\native\\GameHelpersLoader__NEW.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_A_2147936264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.A!MTB"
        threat_id = "2147936264"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 85 c0 79 1d 49 8b 4c 24 08 49 2b 0c 24 48 c1 f9 05 48 ff c9 49 63 c7 48 3b c1 73 05 41 ff c7 eb 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_A_2147936264_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.A!MTB"
        threat_id = "2147936264"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 9c 24 78 01 00 00 48 8b bc 24 50 01 00 00 49 63 e8 40 fe c6 40 c0 ee a0 48 81 c4 58 01 00 00 48 87 ee 66 f7 d5 5e 66 87 ed 5d e9 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {80 7f 01 23 e9 05 00 00 00 0f ca 66 f7 d2 48 8d 57 01 e9 00 00 00 00 0f 85 6c 00 00 00 0f b6 57 02 48 3b f4 48 83 c7 02 84 d2 e9 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AB_2147936266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AB!MTB"
        threat_id = "2147936266"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 c6 85 29 01 00 00 00 41 c6 85 28 01 00 00 00 48 8d 8c 24 00 13 00 00 e8 91 69 14 00 48 8d 8c 24 00 13 00 00 e8 77 6c 14 00 a8 01 0f 85 80 2d 00 00 48 89 17 4c 8d 05 b5 57 2c 00 48 8d 8c 24 50 06 00 00 6a 21 41 59 e8 ae 1c ff ff}  //weight: 2, accuracy: High
        $x_1_2 = "country_code" ascii //weight: 1
        $x_1_3 = "stealer" ascii //weight: 1
        $x_1_4 = "card_number_encrypted" ascii //weight: 1
        $x_1_5 = "credit_cards" ascii //weight: 1
        $x_1_6 = "ejbalbakoplchlghecdalmeeeajnimhm" ascii //weight: 1
        $x_1_7 = "fhbohimaelbohpjbbldcngcnapndodjp" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_B_2147936275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.B!MTB"
        threat_id = "2147936275"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "StealerDLL\\x64\\Release\\STEALERDLL.pdb" ascii //weight: 4
        $x_2_2 = "Monero\\wallets" ascii //weight: 2
        $x_2_3 = "Mozilla Thunderbird" ascii //weight: 2
        $x_1_4 = "9375CFF0413111d3B88A00104B2A6676" ascii //weight: 1
        $x_1_5 = "netsh wlan show profiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_UDP_2147937832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.UDP!MTB"
        threat_id = "2147937832"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 55 51 9c 49 bd 8b ca 09 38 80 26 3c e1 e8 28 f6 fd ff cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_GF_2147938155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GF!MTB"
        threat_id = "2147938155"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8b c1 4d 85 c9 74 22 66 66 0f 1f 84 00 00 00 00 00 48 8b 08 48 83 c0 08 48 89 0a 48 83 c2 08 49 83 e9 01 75 ec 8b 4c 24 48 41 83 e0 07 74 26 48 2b d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AC_2147939484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AC!MTB"
        threat_id = "2147939484"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 48 45 31 c0 41 b9 02 00 00 00 48 c7 c1 01 00 00 80 48 8d 15 ad 37 00 00 48 8d 44 24 38 48 89 44 24 20 ff 15 bd 77 00 00 85 c0 75 61 48 8d 05 d0 37 00 00 41 b9 01 00 00 00 45 31 c0 48 8b 4c 24 38 48 8d 15 ab 37 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EN_2147941353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EN!MTB"
        threat_id = "2147941353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Game Repack Install" wide //weight: 1
        $x_1_2 = {8e 39 44 b9 2a 50 47 b8 8e 39 b8 b8 2a 50 47 b8 2b 50 d0 b8 2a 50 47 b8 8e 39 45 b9 2a 50 47 b8 52 69 63 68 2b 50 47 b8}  //weight: 1, accuracy: High
        $x_1_3 = {2e 74 68 65 6d 69 64 61 00 e0 79 00 00 60 15 00 00 00 00 00 00 b2 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EH_2147942237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EH!MTB"
        threat_id = "2147942237"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 83 eb 05 b9 58 20 99 00 48 29 cb 50 b8 86 15 1c 00 48 01 d8 83 38 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EH_2147942237_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EH!MTB"
        threat_id = "2147942237"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 74 68 65 6d 69 64 61 00 c0 76 00 00 80 18 00 00 00 00 00 00 58 0d}  //weight: 1, accuracy: High
        $x_1_2 = "DVDSetup.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_SX_2147943341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.SX!MTB"
        threat_id = "2147943341"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 c7 44 24 68 07 00 00 00 4c 89 74 24 60 66 44 89 74 24 50 4c 8d 45 60 48 83 7d 78 08 4c 0f 43 45 60 33 d2 b9 01 00 1f 00}  //weight: 15, accuracy: High
        $x_10_2 = {48 89 03 48 83 f8 ff 74 54 33 d2 48 8b c8 ff 15 ?? ?? ?? ?? 89 06 ff c8 83 f8 fd 77 40 48 8b 0b 45 33 c9 48 89 6c 24 28 33 d2 89 6c 24 20 45 8d 41 02 ff 15 ?? ?? ?? ?? 48 89 07 48 85 c0 74 1d 45 33 c9 48 89 6c 24 20 45 33 c0 48 8b c8 41 8d 51 04}  //weight: 10, accuracy: Low
        $x_10_3 = {48 63 4f 3c b8 0b 02 00 00 44 8b 5c 0f 50 48 89 5c 24 40 48 8d 1c 0f 48 89 74 24 48 0f b7 73 06 4c 89 7c 24 20}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_NIT_2147943748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NIT!MTB"
        threat_id = "2147943748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d ac 24 ?? ?? ff ff 48 81 ec ?? ?? ?? ?? 48 8b 05 43 12 02 00 48 33 c4 48 89 85 ?? ?? ?? ?? 4d 8b e0 48 8b f9 48 bb ?? ?? ?? ?? ?? ?? ?? ?? 48 3b d1 74 22 8a 02 2c 2f 3c 2d 77 0a 48 0f be c0 48 0f a3 c3 72 10 48 8b cf e8 d2 ?? ?? ?? 48 8b d0 48 3b c7 75 de}  //weight: 2, accuracy: Low
        $x_3_2 = {b8 40 41 00 00 66 c1 e3 07 b9 80 00 00 00 66 f7 d3 66 23 d9 66 0b d8 4d 85 c0 74 5f 8d 51 ae 49 8b c8 e8 17 1f 01 00 48 8b f0 48 85 c0 74 4c 48 8d 15 ?? ?? ?? ?? 48 8b c8 e8 1c 78 00 00 85 c0 74 3c 48 8d 15 ?? ?? ?? ?? 48 8b ce e8 09 78 00 00 85 c0 74 29 48 8d 15 ?? ?? ?? ?? 48 8b ce e8 f6 77 00 00 85 c0 74 16 48 8d 15 ?? ?? ?? ?? 48 8b ce e8 e3 77 00 00 85 c0 74 03 40 8a fd 48 8b 6c 24 38 0f b7 c3 48 8b 74 24 40 66 83 c8 40 40 84 ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Zusy_NS_2147944940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NS!MTB"
        threat_id = "2147944940"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 0d 81 2e 00 00 ff 15 c3 2a 00 00 48 8d 3d a0 2e 00 00 48 8b d7 48 8d 4d ?? e8 30 02 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = {45 33 c9 48 8d 15 56 2f 00 00 33 c9 ff 15 46 2b 00 00 48 8d 4d ?? e8 65 00 00 00 4c 8b c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_MR_2147945445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.MR!MTB"
        threat_id = "2147945445"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {30 01 48 8d 49 01 ff c0 3b c7 7c}  //weight: 10, accuracy: High
        $x_30_2 = {44 8b c0 b8 4f ec c4 4e 41 f7 e8 c1 fa 03 8b ca c1 e9 1f 03 d1 6b ca 1a 44 2b c1 49 63 c0 0f b6 04 38 88 44 1c 30 48 ff c3 48 83 fb 08}  //weight: 30, accuracy: High
        $x_10_3 = "EyeLoveMyMuteX" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_MR_2147945445_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.MR!MTB"
        threat_id = "2147945445"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b 15 ac 1e 0d 00 8b c2 83 e0 3f 48 8b da 48 33 1d 85 49 0d 00 8b c8 48 d3 cb b9 40 00 00 00 2b c8 48 d3 cf 48 33 fa 48 89 3d 6c 49 0d 00 33 c9}  //weight: 5, accuracy: High
        $x_10_2 = {4c 8b 15 cd 13 0d 00 41 8b ca 49 8b f2 48 33 32 83 e1 3f 4d 8b ca 48 d3 ce 4c 33 4a 08 49 8b da 48 33 5a 10 49 d3 c9 48 d3 cb 4c 3b cb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_HMZ_2147945594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.HMZ!MTB"
        threat_id = "2147945594"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 8a 84 04 ?? ?? ?? ?? 48 63 8c 24 84 00 00 00 48 8b 54 24 48 30 04 0a 8b 84 24 84 00 00 00 83 c0 01 89 44 24 70 8b 05 ?? ?? ?? ?? 8d 48 ff 0f af c8 f6 c1 01 b8 17 f9 ce f2 b9 47 a4 cc 08 0f 44 c1 83 3d a6 5a 09 00 0a 0f 4c c1 44 8b 74 24 44 4d 89 ef e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_LMG_2147946030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.LMG!MTB"
        threat_id = "2147946030"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 8b 44 24 20 48 63 48 04 48 8b 44 0c 68 48 f7 d8 1b d2 f7 d2 83 e2 04 0b 54 0c 30 83 e2 15 83 ca 02 89 54 0c 30 23 54 0c 34}  //weight: 15, accuracy: High
        $x_10_2 = {8b c8 c1 e9 1e 33 c8 69 c1 65 89 07 6c 03 c2 89 44 95 14 ?? ?? ?? 49 3b d0 72 e5 44 89 45 10 [0-4] 48 8d 45 10}  //weight: 10, accuracy: Low
        $x_5_3 = {f2 0f 59 05 ?? ?? ?? ?? 0f 57 c9 48 85 c0 78 ?? f2 48 0f 2a c8 eb ?? 48 8b c8 48 d1 e9 83 e0 01 48 0b c8 f2 48 0f 2a c9 f2 0f 58 c9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_KK_2147946085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.KK!MTB"
        threat_id = "2147946085"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {f3 43 0f 6f 04 08 0f 57 c2 f3 43 0f 7f 04 08 41 8d 42 f0 f3 42 0f 6f 04 08 66 0f 6f ca 0f 57 c8 f3 42 0f 7f 0c 08 41 8b c2 f3 42 0f 6f 04 08 0f 57 c2 f3 42 0f 7f 04 08 41 8d 42 10 f3 42 0f 6f 04 08 66 0f 6f ca 0f 57 c8 f3 42 0f 7f 0c 08 41 83 c0 40 41 83 c2 40 45 3b c3}  //weight: 6, accuracy: High
        $x_10_2 = {41 8d 4a 01 45 8b ca 44 0f b6 04 19 42 0f b6 0c 13 41 80 e8 41 fe c9 49 d1 e9 c0 e1 04 41 83 c2 02 44 0a c1 45 88 04 01 8b 0f 44 3b d1 72 d1}  //weight: 10, accuracy: High
        $x_4_3 = "TuoniAgent.dll" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


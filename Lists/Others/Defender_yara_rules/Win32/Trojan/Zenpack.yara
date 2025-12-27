rule Trojan_Win32_Zenpack_NO_2147763260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.NO!MTB"
        threat_id = "2147763260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 fa 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75 2a 00 8b 4d ?? 8b 55 ?? 8b f3 c1 ee 05 03 75 ?? 03 f9 03 d3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f3 33 f7 29 75 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 50 00 8b 75 ?? c1 ee 05 03 75 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MR_2147770514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MR!MTB"
        threat_id = "2147770514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ee 05 03 [0-3] 81 3d [0-8] c7 05 [0-8] c7 05 [0-8] [0-8] 33 [0-3] 33 [0-3] 2b [0-3] 83 [0-5] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MS_2147771601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MS!MTB"
        threat_id = "2147771601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 08 50 50 ff [0-5] e8 [0-4] 30 [0-3] 81 [0-5] 75 ?? 6a 00 [0-10] ff [0-5] 46 33 [0-3] 3b [0-3] 81}  //weight: 1, accuracy: Low
        $x_1_2 = {75 08 50 50 ff 15 [0-4] e8 [0-4] 30 [0-3] 81 ff [0-4] 75 0f 6a 00 8d [0-3] 50 6a 00 ff 15 [0-4] 46 33 [0-3] 3b [0-3] 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpack_2147771831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MT!MTB"
        threat_id = "2147771831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 37 46 3b f3 55 8b ec 51 81 3d [0-8] a1 [0-8] 69 [0-8] a3 [0-13] 81 [0-8] 8b [0-23] 25 [0-8] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MU_2147771878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MU!MTB"
        threat_id = "2147771878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 33 81 ff [0-4] 46 3b f7 55 8b ec 51 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MV_2147772131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MV!MTB"
        threat_id = "2147772131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 38 40 3b c1 72 ?? a1 [0-4] 8b 0d [0-4] c1 e8 ?? 85 c0 76 13 56 57 8b f9 8b f0 e8 [0-4] 83 c7 08 4e 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MW_2147775503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MW!MTB"
        threat_id = "2147775503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 30 [0-2] 83 [0-2] 46 3b f7 81 3d [0-8] a1 [0-4] 69 [0-5] 05 [0-4] a3 [0-4] 0f [0-6] 81 [0-5] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MK_2147777591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MK!MTB"
        threat_id = "2147777591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b 1a 83 c2 [0-1] 8b 01 42 42 33 c3 89 04 39 58 83 c1 [0-1] 3b 55 08 72 02 8b d6 3b c8 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_XF_2147821042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.XF!MTB"
        threat_id = "2147821042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 10 03 44 24 ?? 89 44 24 ?? 8b 44 24 ?? c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 03 44 24 ?? 33 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c6 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 0f 85}  //weight: 10, accuracy: Low
        $x_1_2 = ".pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EH_2147832150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EH!MTB"
        threat_id = "2147832150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {fd ff ff 0f b6 c8 83 e9 33 8b 95 ?? fd ff ff 89 8d ?? fd ff ff 89 95 d8 fd ff ff 74}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EH_2147832150_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EH!MTB"
        threat_id = "2147832150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 56 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 c7 05 ?? ?? ?? ?? 97 00 00 00 8a 24 0a 28 c4 c7 05 ?? ?? ?? ?? 5d 08 00 00 88 24 0e 5e 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EH_2147832150_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EH!MTB"
        threat_id = "2147832150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MovingtwoDisn.tusEmanland" wide //weight: 1
        $x_1_2 = "oblessedforthunderIthey.re.Bmadethey.re" wide //weight: 1
        $x_1_3 = "watersGqSkFsomFover" wide //weight: 1
        $x_1_4 = "7OnebeastF" wide //weight: 1
        $x_1_5 = "undernSeedSeas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RE_2147832373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RE!MTB"
        threat_id = "2147832373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 62 f8 9f 88 83 c4 04 8a 06 83 c6 01 68 9a 89 70 2d 83 c4 04 32 02 83 ec 04 c7 04 24 f3 29 e6 c5 83 c4 04 88 07 83 c7 01 42}  //weight: 1, accuracy: High
        $x_1_2 = "PnhubgyEctyv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RA_2147832576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RA!MTB"
        threat_id = "2147832576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 95 f3 fe ff ff c6 85 ef fe ff ff 2e c6 85 eb fe ff ff 53 89 e1 8b b5 e4 fe ff ff 89 71 04 c7 41 08 04 01 00 00 c7 01 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_NE_2147833196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.NE!MTB"
        threat_id = "2147833196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "nihulebucino" ascii //weight: 5
        $x_5_2 = "Vuxotikuwuj" wide //weight: 5
        $x_5_3 = "gocugazutecojuj" wide //weight: 5
        $x_5_4 = "pofigiyakoyufude" ascii //weight: 5
        $x_1_5 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "GetProcAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_ED_2147833989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.ED!MTB"
        threat_id = "2147833989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {5d c3 8d 05 ?? ?? ?? ?? 89 25 ?? ?? ?? ?? eb 05 e9 ?? ?? ?? ?? 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? b9 03 00 00 00 89 e8 01 05 ?? ?? ?? ?? 89 f8 01 ?? ?? ?? ?? ?? e2 d4 c3 89 45}  //weight: 4, accuracy: Low
        $x_1_2 = "ret.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EC_2147834039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EC!MTB"
        threat_id = "2147834039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 20 83 f2 07 42 01 d0 eb 30 83 f0 04 42}  //weight: 3, accuracy: High
        $x_2_2 = {31 18 83 e8 04 01 d0 8d 05 ?? ?? ?? ?? 31 30 e9 ab fa ff ff c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EC_2147834039_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EC!MTB"
        threat_id = "2147834039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {66 6a 00 2d 83 11 00 00 50 ff 14 24 89 d9 89 0d ?? ?? ?? ?? 89 f1 89 0d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 39 3d ?? ?? ?? ?? 74 bb}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EC_2147834039_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EC!MTB"
        threat_id = "2147834039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {83 ea 05 89 e8 50 8f 05 ?? ?? ?? ?? e9 e6 f5 ff ff c3 8d 05 ?? ?? ?? ?? 31 18 01 d0 31 c2 89 f0 50 8f 05 ?? ?? ?? ?? 31 3d ?? ?? ?? ?? eb d1}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EC_2147834039_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EC!MTB"
        threat_id = "2147834039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "meatgiven,6likenessZj" ascii //weight: 1
        $x_1_2 = "zmanklifeznJ1Q" ascii //weight: 1
        $x_1_3 = "beastjhave." ascii //weight: 1
        $x_1_4 = "h1green6twoevening5dZi" ascii //weight: 1
        $x_1_5 = "sawkI" ascii //weight: 1
        $x_1_6 = "UsthirdCattlegreensixth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EC_2147834039_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EC!MTB"
        threat_id = "2147834039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qmtherethe6setIstarssmorning" ascii //weight: 1
        $x_1_2 = "1n2rj96wasj" ascii //weight: 1
        $x_1_3 = "Lwhoseformuponflyhaveua.two" ascii //weight: 1
        $x_1_4 = "ORFthemwatershthemw" ascii //weight: 1
        $x_1_5 = "f0them1place.hismoved.dXabundantly" ascii //weight: 1
        $x_1_6 = "multiplyopen.9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EM_2147834103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EM!MTB"
        threat_id = "2147834103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 e4 31 c9 89 c2 88 d3 8b 55 e8 88 1c 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EM_2147834103_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EM!MTB"
        threat_id = "2147834103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c1 e0 04 89 01 c3 81 00 e1 34 ef c6 c3 01 08 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EM_2147834103_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EM!MTB"
        threat_id = "2147834103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 20 b9 02 00 00 00 e2 11 4a 4a 89 e8 50 8f 05 ?? ?? ?? ?? e9 ?? ?? ?? ?? c3 42 83 c2 07 29 c2 8d 05 ?? ?? ?? ?? 31 38 83 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EM_2147834103_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EM!MTB"
        threat_id = "2147834103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {83 ec 0c 89 e1 c7 41 04 8d 0c 00 00 c7 01 18 05 00 00}  //weight: 3, accuracy: High
        $x_2_2 = {83 ec 04 88 44 24 1b e9 60 fb ff ff 8d 65 f8 5e 5f 5d c3 40}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EM_2147834103_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EM!MTB"
        threat_id = "2147834103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fruittree9own" ascii //weight: 1
        $x_1_2 = "airRfirmamentZ" ascii //weight: 1
        $x_1_3 = "thingkfortwodeepstarsOgreen" ascii //weight: 1
        $x_1_4 = "GlobalAlloc" ascii //weight: 1
        $x_1_5 = "LoadResource" ascii //weight: 1
        $x_1_6 = "DeviceIoControl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EM_2147834103_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EM!MTB"
        threat_id = "2147834103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loader.cpp.bc.obj.pdb" ascii //weight: 1
        $x_1_2 = "dominion8creepethzHismovedFishgG" ascii //weight: 1
        $x_1_3 = "one2KtwoYou.re" ascii //weight: 1
        $x_1_4 = "ReplenishNgathering" ascii //weight: 1
        $x_1_5 = "CreatePointerMoniker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EM_2147834103_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EM!MTB"
        threat_id = "2147834103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "For.f9uponNSfowlsoshe.dGreater" ascii //weight: 1
        $x_1_2 = "MakeHUbroughtfish" ascii //weight: 1
        $x_1_3 = "heavenHeavenkindCElseedgreater" ascii //weight: 1
        $x_1_4 = "femalemultiplyQvery,12cUf" ascii //weight: 1
        $x_1_5 = "can.tcreated.1aPgoodwon.tIoj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EM_2147834103_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EM!MTB"
        threat_id = "2147834103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hformdryAismeatseasons.thirdB" ascii //weight: 1
        $x_1_2 = "day.movingOFromeQtheyou" ascii //weight: 1
        $x_1_3 = "umoveth.sayingsaying" ascii //weight: 1
        $x_1_4 = "wasdayherb,upon.earthlet.LLcreepethmay" ascii //weight: 1
        $x_1_5 = "dthDarknessPli3evening,Green" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EM_2147834103_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EM!MTB"
        threat_id = "2147834103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setbehold,blessedYletflyabundantly2rg" wide //weight: 1
        $x_1_2 = "LightyLFx" wide //weight: 1
        $x_1_3 = "their,uponKiskwinged7upon" wide //weight: 1
        $x_1_4 = "MofSubduemadegivenh" wide //weight: 1
        $x_1_5 = "TESTAPP.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EM_2147834103_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EM!MTB"
        threat_id = "2147834103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VhbeginningKf5seasayingthem" wide //weight: 1
        $x_1_2 = "8XOgrassusetPlace" wide //weight: 1
        $x_1_3 = "Xfaceundersigns.tRitself3Dn" wide //weight: 1
        $x_1_4 = "0can.t0firmamentdayGreatersecond,creeping" wide //weight: 1
        $x_1_5 = "Thirdmovedstarsthem" wide //weight: 1
        $x_1_6 = "emovingbcreepingrmayrourXcreeping" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EA_2147834379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EA!MTB"
        threat_id = "2147834379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AztfacenIfor.G" ascii //weight: 1
        $x_1_2 = "FLivingdryptdaysforthBq" ascii //weight: 1
        $x_1_3 = "beopengiveRdayncan.t" ascii //weight: 1
        $x_1_4 = "GDivide.openqflyNdQ" ascii //weight: 1
        $x_1_5 = "C*+.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EN_2147834729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EN!MTB"
        threat_id = "2147834729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {b9 03 00 00 00 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? e2 d0 31 c0 40 c3 89 45 00 d0 d0 d0 d0 d0 d0 d0 d0}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EN_2147834729_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EN!MTB"
        threat_id = "2147834729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "togetherLightSubdue.Wappear" ascii //weight: 1
        $x_1_2 = "IMoving.heavenpum" ascii //weight: 1
        $x_1_3 = "GBkWZmeatDm" ascii //weight: 1
        $x_1_4 = "w8TAboveJVinmadeown.may" ascii //weight: 1
        $x_1_5 = "ofsayingfNmovedseas" ascii //weight: 1
        $x_1_6 = "qYIxUBeginningmhimearth" ascii //weight: 1
        $x_1_7 = "*iq80RACJKZ2tjrw.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8b 55 d8 8b 7d e4 0f b6 14 17 31 d1 88 cb 8b 4d d4 8b 55 e8 88 1c 0a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? e2 d4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {ff e0 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? e2 d7}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? 83 f9 67 74 d1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {ff ff 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? 83 f9 0a 74 d1}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {31 18 ba 01 00 00 00 4a 8d 05 ?? ?? ?? ?? 31 38 01 c2 4a 8d 05 ?? ?? ?? ?? 01 28 01 c2 4a 8d 05 ?? ?? ?? ?? 89 30 eb cc}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {ff ff 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? b9 03 00 00 00 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? e2 d5 31 c0 40 c3}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {49 89 ca 89 25 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? eb da}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {40 83 ea 05 01 d0 83 f0 01 01 25 ?? ?? ?? ?? 31 d0 29 c2 29 d0 b9 02 00 00 00 e2 2d 4a 83 f2 07 ba 04 00 00 00 8d 05 ?? ?? ?? ?? 31 28 8d 05}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {89 d0 b9 03 00 00 00 49 89 ca 89 25 ?? ?? ?? ?? eb 08 8d 05 ?? ?? ?? ?? ff e0 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {89 d0 b9 03 00 00 00 49 89 ca 89 25 ?? ?? ?? ?? eb 05 e8 ?? ?? ?? ?? 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? eb da}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {40 55 89 e5 eb 25 31 2d ?? ?? ?? ?? 58 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? 04 00 00 00 a1 ?? ?? ?? ?? 66 6a 00 2d 83 11 00 00 ff d0 89 d9 89 0d ?? ?? ?? ?? 89 f1 89 0d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 39 3d ?? ?? ?? ?? 74 bd}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff d0 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? eb d7 89 45}  //weight: 5, accuracy: Low
        $x_1_2 = "OutputDebugStringA" ascii //weight: 1
        $x_1_3 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AOIj89sghj4siohjrh" ascii //weight: 1
        $x_1_2 = "IosbvserioHjerIsh" ascii //weight: 1
        $x_1_3 = "Opxvbsege4hrhirtj" ascii //weight: 1
        $x_1_4 = "Uyiawsprgjw40ghsreh" ascii //weight: 1
        $x_1_5 = "iosgo4jgsrohsjrohi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EB_2147835055_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EB!MTB"
        threat_id = "2147835055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "multiplytN5Thingqfifth" wide //weight: 1
        $x_1_2 = "PreplenishiwhoseaDBs" wide //weight: 1
        $x_1_3 = "pydividedyou.lll" wide //weight: 1
        $x_1_4 = "movingfowlthelbring" wide //weight: 1
        $x_1_5 = "creeping,L5HCan.t" wide //weight: 1
        $x_1_6 = "The3LAXin.gItselfn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_NEAA_2147836097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.NEAA!MTB"
        threat_id = "2147836097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "yielding,5twomakeS5" ascii //weight: 5
        $x_5_2 = "setusshe.dMaleappearh" ascii //weight: 5
        $x_5_3 = "gatheredlesserdaythere.kseeditshe.d" ascii //weight: 5
        $x_5_4 = "vommde.pdb" ascii //weight: 5
        $x_5_5 = "WdividedPformB" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_NEAB_2147836973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.NEAB!MTB"
        threat_id = "2147836973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {75 1c 8b 45 e4 8b 48 02 8b 09 8a 11 80 fa ff 89 ce 89 75 f8 89 4d f4 88 55 f3 74 da eb 0b 8b 45 e4 8a 08 89 45 f4 88 4d f3 8a 45 f3 8b 4d f4 31 d2 88 d4 3c b8 89 4d ec}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_CB_2147838803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.CB!MTB"
        threat_id = "2147838803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {ff d0 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? eb d7}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_CB_2147838803_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.CB!MTB"
        threat_id = "2147838803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {49 89 ca 89 25 ?? ?? ?? ?? eb 05 e8 ?? ?? ?? ?? 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? eb da}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_CB_2147838803_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.CB!MTB"
        threat_id = "2147838803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {55 89 e5 eb 1f 89 2d ?? ?? ?? ?? 58 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? 04 00 00 00 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 d9 89 0d ?? ?? ?? ?? 89 f1 89 0d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? eb c9}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_CB_2147838803_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.CB!MTB"
        threat_id = "2147838803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {55 89 e5 eb 1f 89 2d ?? ?? ?? ?? 58 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? 04 00 00 00 66 6a 00 50 e8 ?? ?? ?? ?? 89 d9 89 0d ?? ?? ?? ?? 89 f1 89 0d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? eb c9 89 45}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_NEAC_2147839719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.NEAC!MTB"
        threat_id = "2147839719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "placeemultiply,WtheUnto" ascii //weight: 2
        $x_2_2 = "Formyearsis" ascii //weight: 2
        $x_2_3 = "RXforth." ascii //weight: 2
        $x_2_4 = "aourcmidst" ascii //weight: 2
        $x_2_5 = "GXunderpsawtehad0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_NEAD_2147839738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.NEAD!MTB"
        threat_id = "2147839738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 08 89 45 f8 8b 45 f8 89 45 f4 8b 45 f4 0f b6 00 3d ff 00 00 00 74 15 eb 36 8a 45 f3 24 01 0f b6 c8 89 4d fc 8b 45 fc 83 c4 14 5d}  //weight: 10, accuracy: High
        $x_5_2 = "were.one6multiplylcreature." wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EG_2147842515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EG!MTB"
        threat_id = "2147842515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ea 05 89 e8 50 8f 05 ?? ?? ?? ?? e9 ?? ?? ?? ?? c3 8d 05 ?? ?? ?? ?? 31 18 01 d0 31 c2 89 f0 50 8f 05 ?? ?? ?? ?? 31 3d ?? ?? ?? ?? eb d1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_NEAE_2147843628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.NEAE!MTB"
        threat_id = "2147843628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Creepingyabundantly" ascii //weight: 2
        $x_2_2 = "be4they.re.1their.Kface" ascii //weight: 2
        $x_2_3 = "7creepethino" ascii //weight: 2
        $x_2_4 = "underisn.tmadesawfseedV" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MKV_2147845226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MKV!MTB"
        threat_id = "2147845226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 fe 81 e6 ?? ?? ?? ?? 8b 7d ?? 8a 1c 0f 8b 7d ?? 32 1c 37 8b 75 ?? 88 1c 0e 81 c1 ?? ?? ?? ?? 8b 75 ?? 39 f1 8b 75 ?? 89 4d ?? 89 75 ?? 89 55 ?? 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MKW_2147845242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MKW!MTB"
        threat_id = "2147845242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 fe 81 e6 ?? ?? ?? ?? 8b 7d ?? 8a 1c 0f 8b 7d ?? 32 1c 37 8b 75 ?? 88 1c 0e 81 c1 ?? ?? ?? ?? 8b 75 ?? 39 f1 8b 75 ?? 89 4d ?? 89 75 ?? 89 55 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MKP_2147845383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MKP!MTB"
        threat_id = "2147845383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f3 81 e3 ?? ?? ?? ?? 8b 75 ?? 8b 4d ?? 8a 0c 0e 8b 75 ?? 32 0c 1e 8b 5d ?? 8b 75 ?? 88 0c 33 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 4d ?? 39 cf 8b 4d ?? 89 55 ?? 89 4d ?? 89 7d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_SK_2147847464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.SK!MTB"
        threat_id = "2147847464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thirdfemalefishgreen." ascii //weight: 1
        $x_1_2 = "OSplace.scattleslYieldingPsaw." ascii //weight: 1
        $x_1_3 = "Don.twemakeeveninggmadeall.created.J" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPY_2147849727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPY!MTB"
        threat_id = "2147849727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 8d c8 fe ff ff 80 39 53 0f 94 c3 8b 95 c4 fe ff ff 80 3a 54 0f 94 c7 20 fb 8b b5 c0 fe ff ff 80 3e 45 0f 94 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPY_2147849727_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPY!MTB"
        threat_id = "2147849727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 f1 58 00 00 00 89 d7 01 f7 81 c7 04 00 00 00 69 f1 58 00 00 00 01 f2 81 c2 2c 00 00 00 81 c1 01 00 00 00 8b 12 0f b7 37 31 d6 01 c6 81 f9 d4 01 00 00 89 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPY_2147849727_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPY!MTB"
        threat_id = "2147849727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 85 ec fd ff ff 89 85 cc fc ff ff b8 1e 00 00 00 8d 8d ec fd ff ff 89 ca 81 c2 0a 00 00 00 89 ce 81 c6 06 00 00 00 89 cf 81 c7 10 00 00 00 89 cb 81 c3 0e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPY_2147849727_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPY!MTB"
        threat_id = "2147849727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d fc 8b 91 ac 00 00 00 03 42 3c 8b 4d fc 6b 91 c8 04 00 00 28 8d 84 10 f8 00 00 00 8b 4d fc 89 81 b4 04 00 00 6a 00 8b 55 fc 8b 82 b4 04 00 00 8b 48 10 51 8b 4d fc 83 c1 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPY_2147849727_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPY!MTB"
        threat_id = "2147849727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 80 bd 06 ff ff ff 2e 0f 94 c1 8b 95 e8 fe ff ff 80 3a 54 0f 94 c5 20 e9 f6 c1 01 89 85 ec fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {ff d0 83 ec 04 3d 00 00 00 00 0f 94 c1 88 8d e7 fe ff ff 8a 85 e7 fe ff ff a8 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPX_2147851089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPX!MTB"
        threat_id = "2147851089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 85 e4 fe ff ff ff d1 83 ec 04 8b 8d e4 fe ff ff 81 c1 01 00 00 00 89 e2 89 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPX_2147851089_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPX!MTB"
        threat_id = "2147851089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d0 8b 4d d4 8b 55 d8 be 00 01 00 00 81 c1 01 00 00 00 89 45 cc 89 c8 89 55 c8 99 f7 fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPX_2147851089_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPX!MTB"
        threat_id = "2147851089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4d a8 8b 4d ac 89 48 0c 89 58 04 8b 4d a8 89 08 c7 40 08 04 00 00 00 89 7d a4 89 55 a0 89 75 9c ff d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPX_2147851089_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPX!MTB"
        threat_id = "2147851089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 eb 1b 89 f8 50 8f 05 ?? ?? ?? ?? 40 42 01 c2 31 35 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? ff e0 40 89 d8 50 8f 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPX_2147851089_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPX!MTB"
        threat_id = "2147851089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 8d 9b 00 00 00 00 83 3d ?? ?? ?? 00 0b 75 0e 8d 8c 24 2c 01 00 00 51 6a 00 6a 00 ff d7 81 fe 4c 13 00 00 0f 85 19 0b 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPX_2147851089_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPX!MTB"
        threat_id = "2147851089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 85 80 fc ff ff ff d1 83 ec 0c 8b 8d cc fc ff ff 66 81 39 45 00 0f 94 c3 8b 95 bc fc ff ff 66 81 3a 4c 00 0f 94 c7 20 fb 8b b5 b8 fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPX_2147851089_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPX!MTB"
        threat_id = "2147851089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 5e a8 66 32 f7 64 24 1c 8b 44 24 1c 81 6c 24 0c 00 02 32 55 81 44 24 34 9f 12 a5 12 b8 bf 91 2a 1d f7 64 24 10 8b 44 24 10 81 6c 24 3c fa 7a 76 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPX_2147851089_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPX!MTB"
        threat_id = "2147851089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 80 bd 06 ff ff ff 2e 0f 94 c1 8b 95 ec fe ff ff 80 3a 54 0f 94 c5 20 e9 f6 c1 01 89 85 f0 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8d 85 fc fe ff ff 05 04 00 00 00 89 85 e8 fe ff ff 8b 85 e8 fe ff ff 80 38 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPZ_2147851090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPZ!MTB"
        threat_id = "2147851090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 48 42 39 4e 37 36 32 43 33 83 c4 04 eb 03 50 47 4e 59 8b 0f ff 77 08 8b 45 00 03 cb 51 8b cd ff 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPZ_2147851090_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPZ!MTB"
        threat_id = "2147851090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 80 bd 06 ff ff ff 2e 0f 94 c1 8b 95 e4 fe ff ff 80 3a 54 0f 94 c5 20 e9 f6 c1 01 89 85 f0 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {ff d0 83 ec 0c 8d 8d fc fe ff ff c7 85 f8 fe ff ff ff ff ff ff 81 c1 03 00 00 00 80 bd ff fe ff ff 53 89 85 e8 fe ff ff 89 8d e4 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_RPZ_2147851090_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.RPZ!MTB"
        threat_id = "2147851090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 85 9c fc ff ff ff d1 83 ec 0c 8b 8d a4 fc ff ff 66 81 39 53 00 0f 94 c3 8b 95 a0 fc ff ff 66 81 3a 45 00 0f 94 c7 20 fb 8b b5 b8 fc ff ff 66 81 3e 2e 00 0f 94 c7 20 fb 8b bd a8 fc ff ff 66 81 3f 4c 00 0f 94 c7}  //weight: 1, accuracy: High
        $x_1_2 = {89 85 94 fc ff ff ff d1 83 ec 0c 8b 8d 9c fc ff ff 66 81 39 53 00 0f 94 c3 8b 95 98 fc ff ff 66 81 3a 45 00 0f 94 c7 20 fb 8b b5 b0 fc ff ff 66 81 3e 2e 00 0f 94 c7 20 fb 8b bd a0 fc ff ff 66 81 3f 4c 00 0f 94 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpack_MBHK_2147852448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MBHK!MTB"
        threat_id = "2147852448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wuwarasazimofaxazigesevuhu" ascii //weight: 1
        $x_1_2 = "tolixoyusojuxodojabun tuwacekicikegevojucef heduximinajigih" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_DA_2147888186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.DA!MTB"
        threat_id = "2147888186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d9 01 de 81 e6 ff 00 00 00 8b 1d ?? ?? ?? ?? 81 c3 9e f4 ff ff 89 1d ?? ?? ?? ?? 8b 5d ?? 8b 4d ?? 8a 0c 0b 8b 5d ?? 32 0c 33 8b 75 ?? 8b 5d ?? 88 0c 1e 8b 0d ?? ?? ?? ?? 81 c1 27 eb ff ff 89 0d ?? ?? ?? ?? 8b 4d ?? 39 cf 8b 4d ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MBIK_2147889396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MBIK!MTB"
        threat_id = "2147889396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wimadinawococay yujuyumoveroso" wide //weight: 1
        $x_1_2 = "Powutari kuhagilet luxuloyih" wide //weight: 1
        $x_1_3 = "setovuheyivukacapokopeh" wide //weight: 1
        $x_1_4 = "hiwaticayokimacusavefuji" wide //weight: 1
        $x_1_5 = "vujefevotopulakocidam" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MBJV_2147893170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MBJV!MTB"
        threat_id = "2147893170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 61 68 61 6e 65 6b 75 63 6f 66 69 6a 61 6a 69 77 61 77 00 73 65 77 6f 6d 65 78 69 6b 69 6a 61 6c 6f 64 65 64 65 6c 65 76 65 20 73 6f 79 75 67 6f 6c 6f 72 61 63 69 20 79 61 6d 61 7a 69 64 00 72 75 6a 65 68 75 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MBKE_2147893492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MBKE!MTB"
        threat_id = "2147893492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 4c 81 3d ?? ?? ?? ?? ?? ?? 00 00 a1 ?? ?? ?? ?? 8a 84 30 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 04 31 75}  //weight: 1, accuracy: Low
        $x_1_2 = "rujehulayafaligubovotodeho" ascii //weight: 1
        $x_1_3 = "Zupowu naletuyalejozon" ascii //weight: 1
        $x_1_4 = "Jufupupezunile gaxekemutuxev" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MBKF_2147893505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MBKF!MTB"
        threat_id = "2147893505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 71 68 65 6e 72 6e 65 77 64 36 38 2e 64 6c 6c 00 45 61 6c 45 73 6e 65 61 74 61 79 73 78 78 74}  //weight: 1, accuracy: High
        $x_1_2 = "z:\\vEAi\\j1KsWp.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_MBKI_2147893570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.MBKI!MTB"
        threat_id = "2147893570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 6e 72 6e 6e 6c 72 73 65 6e 37 36 2e 64 6c 6c 00 54 61 72 65 74 78 6f 70 6e 6e 65 76 6e 4e 74 69 74 78 00 6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_NC_2147912383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.NC!MTB"
        threat_id = "2147912383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hisixirerowu zekocofu" ascii //weight: 1
        $x_1_2 = "Megoyoladuxinev" ascii //weight: 1
        $x_1_3 = "Fazegokopedoga" ascii //weight: 1
        $x_1_4 = "Cusezapumuhut" ascii //weight: 1
        $x_1_5 = "Kuyumopekoyadeg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_YAB_2147916575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.YAB!MTB"
        threat_id = "2147916575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af d6 88 d0 a2 ?? ?? ?? ?? 8a 45 fa a2 ?? ?? ?? ?? 8a 45 fb a2 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? 31 f2 88 d0 a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpack_EGQN_2147947298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpack.EGQN!MTB"
        threat_id = "2147947298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 4c 24 15 8b 44 24 18 0f b6 54 24 16 88 0c 03 0f b6 4c 24 17 43 88 14 03 8b 54 24 20 43 88 0c 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


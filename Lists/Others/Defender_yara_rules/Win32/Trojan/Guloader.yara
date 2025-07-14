rule Trojan_Win32_Guloader_VT_2147753005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.VT!MTB"
        threat_id = "2147753005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "Zf2BYWfiaKVfGnJ178AopcHk2hO8lnKYeS7uZT96" wide //weight: 1
        $x_1_3 = "pfiHbnPzvSeYGnQYnteZ7aLU3tAo12" wide //weight: 1
        $x_1_4 = "Brqc2LRUdA252" wide //weight: 1
        $x_1_5 = "a1HQ4QRNaXzHvZzKD8Lp7uxTrs9L239" wide //weight: 1
        $x_1_6 = "QWQhsCvsGS9wNZL2jpN69" wide //weight: 1
        $x_1_7 = "dVpnLn7lIfzVp6xRsC8MLI1OLDKpW26" wide //weight: 1
        $x_1_8 = {ff 37 81 fb}  //weight: 1, accuracy: High
        $x_1_9 = {31 f1 81 fa}  //weight: 1, accuracy: High
        $x_1_10 = {09 0c 10 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Guloader_VT_2147753005_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.VT!MTB"
        threat_id = "2147753005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 37 66 3d [0-64] [0-64] [0-64] 31 f1 [0-64] [0-64] 01 0c 10}  //weight: 5, accuracy: Low
        $x_5_2 = {ff 37 66 85 [0-64] [0-64] [0-64] 31 f1 [0-64] [0-64] 01 0c 10}  //weight: 5, accuracy: Low
        $x_5_3 = {ff 37 66 83 [0-64] [0-64] [0-64] 31 f1 [0-64] [0-64] 01 0c 10}  //weight: 5, accuracy: Low
        $x_5_4 = {ff 37 66 81 [0-64] [0-64] [0-64] 31 f1 [0-64] [0-64] 01 0c 10}  //weight: 5, accuracy: Low
        $x_5_5 = {ff 37 eb 05 [0-64] [0-64] [0-64] 31 f1 [0-64] [0-64] 01 0c 10}  //weight: 5, accuracy: Low
        $x_5_6 = {ff 37 eb 0d [0-64] [0-64] [0-64] 31 f1 [0-64] [0-64] 01 0c 10}  //weight: 5, accuracy: Low
        $x_5_7 = {ff 37 81 fa [0-64] [0-64] [0-64] 31 f1 [0-64] [0-64] 01 0c 10}  //weight: 5, accuracy: Low
        $x_5_8 = {ff 37 85 db [0-64] [0-64] [0-64] 31 f1 [0-64] [0-64] 01 0c 10}  //weight: 5, accuracy: Low
        $x_1_9 = "STdqF2uzqguKCOOch5wNz8M8AlI35" wide //weight: 1
        $x_1_10 = "hKh4WcN2HlqkyFTL48" wide //weight: 1
        $x_1_11 = "zQgJSIwxMbPFxMJdle2CuWA6SBpsD5X59zLfdVc28" wide //weight: 1
        $x_1_12 = "M79pkoUDe3ZvE3B5RJLa67" wide //weight: 1
        $x_1_13 = "RWfnOdf3Q2f0vSAFF7UII31" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Guloader_GM_2147753014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.GM!MTB"
        threat_id = "2147753014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetTempFileNameW" ascii //weight: 1
        $x_1_2 = "SendMessageW" ascii //weight: 1
        $x_1_3 = "SHBrowseForFolderW" ascii //weight: 1
        $x_1_4 = "SHGetSpecialFolderLocation" ascii //weight: 1
        $x_1_5 = "InitiateShutdownW" ascii //weight: 1
        $x_1_6 = "SetDefaultDllDirectories" ascii //weight: 1
        $x_5_7 = "SeShutdownPrivilege" wide //weight: 5
        $x_1_8 = "\\Temp" wide //weight: 1
        $x_5_9 = "loyaliteters radierne.exe" wide //weight: 5
        $x_5_10 = "Malwarebytes Corporation" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Guloader_GM_2147753014_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.GM!MTB"
        threat_id = "2147753014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nc2VIR3XvZkpBIv7XmFHoP7XYgxKIVd230" wide //weight: 1
        $x_1_2 = "D1kdDSyrpib66108" wide //weight: 1
        $x_1_3 = "EShdGrMmxdOAepJD0AU8y1E5rj9EOkW545" wide //weight: 1
        $x_1_4 = "NYM33PEqjiPncuO0Rb4raFAjzLBsOiDT9sJ1M130" wide //weight: 1
        $x_1_5 = "IpWrNC6MCTrxbVpMmZIBRG74GYn89" wide //weight: 1
        $x_1_6 = "hXcBg6Iq176" wide //weight: 1
        $x_1_7 = "uJrYCpzniYeysxG3Fc8AGpRApoLIPVXQqr240" wide //weight: 1
        $x_1_8 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_GG_2147753227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.GG!MTB"
        threat_id = "2147753227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f ef d7 81 [0-5] c3 99 00 ff 37 [0-30] 31 34 24 [0-30] 8f 04 10 [0-82] 81 fa [0-4] 75 [0-30] ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AK_2147753825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AK!MTB"
        threat_id = "2147753825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0f 85 d2 e8 ?? ?? 00 00 85 c0 39 c1 75 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 02 00 00 ff e0}  //weight: 1, accuracy: High
        $x_1_3 = {0f 6e da 66 85 db 31 f1 85 ff c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AK_2147753825_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AK!MTB"
        threat_id = "2147753825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rot13.c" wide //weight: 1
        $x_1_2 = "view-list-symbolic.svg" wide //weight: 1
        $x_1_3 = "28.25.1" wide //weight: 1
        $x_1_4 = "GARBAGESTRINGBLOCK" wide //weight: 1
        $x_1_5 = "XORSTRINGPASS" wide //weight: 1
        $x_1_6 = "kernel32.dll::SwitchToThread()" wide //weight: 1
        $x_1_7 = "Adventure_18.bmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AK_2147753825_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AK!MTB"
        threat_id = "2147753825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Munkens\\Serotypes\\Insecable.lnk" ascii //weight: 1
        $x_1_2 = "Udsolgtes\\Skudgarns\\Identitetsflelse.Bel" ascii //weight: 1
        $x_1_3 = "Spartlings\\Tropsfrerens\\Desolately\\Pleskenerne.Amb" ascii //weight: 1
        $x_1_4 = "Lygterne\\Ilona\\Abscissions.Brd" ascii //weight: 1
        $x_1_5 = "Vejledningens\\Styretjskontrollens\\Autodafsxers\\Meazel.dll" ascii //weight: 1
        $x_1_6 = "Dopped\\Drmmers251\\Daasesag.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AL_2147753826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AL!MTB"
        threat_id = "2147753826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f8 81 dc fc 01 00 00 40 55 89 e5 e8 00 00 00 00 58 83 e8 10 89 45 44 e8 ?? ?? 00 00 e9 ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {31 10 f8 83 c0 04 39 d8 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {64 8b 1d c0 00 00 00 81 fe ?? ?? ?? ?? 83 fb 00 74 26 eb 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AL_2147753826_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AL!MTB"
        threat_id = "2147753826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Brunsttids\\Bigfeet\\Erhvervshmmedes33\\Syncs.Tib" wide //weight: 1
        $x_1_2 = "Software\\Demoniast\\Noncredibility\\Insufficiensers" wide //weight: 1
        $x_1_3 = "Rowe\\Wilbert\\efterslts.ini" wide //weight: 1
        $x_1_4 = "Tavshedspligts\\Urmenneskers.lnk" wide //weight: 1
        $x_1_5 = "Watercolored.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_OW_2147754174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.OW!MTB"
        threat_id = "2147754174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 5b 81 fa e2 30 ef 66 85 d2 66 85 d2 3d e9 c0 ec d5 01 d3 85 c0 85 c0 85 db 66 85 c0 09 0b 81 ff e7 67 09 58 85 d2 66 85 db eb 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AM_2147754207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AM!MTB"
        threat_id = "2147754207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 cb d9 d0 [0-8] 75 50 00 4a [0-21] 29 db [0-21] 0b 1a [0-32] 39 cb d9 d0 [0-8] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {46 85 ff 8b 0f [0-8] 0f 6e c6 [0-8] 0f 6e c9 [0-8] 0f ef c8 [0-8] 0f 7e c9 [0-8] 39 c1 [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_OH_2147754294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.OH!MTB"
        threat_id = "2147754294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 66 85 d2 85 ff 85 db 85 c0 5b 66 85 db 85 db 66 81 ff a4 83 85 d2 01 d3 3d 4e 57 1c 2c 85 d2 66 3d 29 bb 09 0b eb 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_GZ_2147754346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.GZ!MTB"
        threat_id = "2147754346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 85 c0 66 85 db 5b 85 d2 66 81 ff f7 94 01 d3 85 db 81 fa e6 c1 f5 a6 31 0b 85 db e9 b2 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_OM_2147754350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.OM!MTB"
        threat_id = "2147754350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 81 fa 3e 29 85 db 01 d3 66 85 db 85 ff 31 0b 81 fb 9d e0 fc 81 66 85 c0 83 c2 04 85 db e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AG_2147754747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AG!MTB"
        threat_id = "2147754747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cqSuooxaLpiBvc9FFUDA5nmhApVQrwTj4JdIZMKi33" wide //weight: 1
        $x_1_2 = "zStTV3pMkYAL7EHfoQhgoU7UaN92prlfDm25Aot245" wide //weight: 1
        $x_1_3 = "Idd5w44C0DudVZnZxDdhjtqLUUQBidG3kev167" wide //weight: 1
        $x_1_4 = "IrtXb6t9dlZekd46EOOxxEWqjpLUc177" wide //weight: 1
        $x_1_5 = "QMd9M77ZU0SH8yJPNBLztdfh3233" wide //weight: 1
        $x_1_6 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AI_2147754748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AI!MTB"
        threat_id = "2147754748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Overbelaste\\Theatricals.dll" ascii //weight: 1
        $x_1_2 = "heriaphor.ini" ascii //weight: 1
        $x_1_3 = "manyplies\\Terrorgruppernes\\Bervelse\\Hypnotically\\Udsparings.Unh" ascii //weight: 1
        $x_1_4 = "Blueback\\diphtheriaphor.ini" ascii //weight: 1
        $x_1_5 = "Maaleforstrkere70\\Describable.Uns" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AI_2147754748_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AI!MTB"
        threat_id = "2147754748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Baakersrindu4" wide //weight: 1
        $x_1_2 = "Notariza5" wide //weight: 1
        $x_1_3 = "Sikkerhe4" wide //weight: 1
        $x_1_4 = "Manage9" wide //weight: 1
        $x_1_5 = "Montebrasi4" wide //weight: 1
        $x_1_6 = "Hjpasteuris" wide //weight: 1
        $x_1_7 = "Toninge" wide //weight: 1
        $x_1_8 = "SASSOL" wide //weight: 1
        $x_1_9 = "Paradiddl7" wide //weight: 1
        $x_1_10 = "overbevo" wide //weight: 1
        $x_1_11 = "outtradings" wide //weight: 1
        $x_1_12 = "stetiseretha" wide //weight: 1
        $x_1_13 = "skiftingers" wide //weight: 1
        $x_1_14 = "Teaselers" wide //weight: 1
        $x_1_15 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_LL_2147754927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.LL!MTB"
        threat_id = "2147754927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 52 f4 66 3d 74 75 81 fa 2b 9d 52 0d 81 fb f8 6f e8 3e 31 34 24 85 d2 66 85 c0 81 fa c3 89 ef df 66 3d b3 d1 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_VB_2147755076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.VB!MTB"
        threat_id = "2147755076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 34 0a 81 f6 [0-5] 89 34 08 83 e9 [0-5] 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_VB_2147755076_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.VB!MTB"
        threat_id = "2147755076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "Dublanternes" wide //weight: 1
        $x_1_3 = "besgelsestiden" wide //weight: 1
        $x_1_4 = "Tuberkulins" wide //weight: 1
        $x_1_5 = "Fricandelle8" wide //weight: 1
        $x_1_6 = "Aalekvabben1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_VB_2147755076_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.VB!MTB"
        threat_id = "2147755076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "TOLVAARSFDSELSDAGENES" wide //weight: 1
        $x_1_3 = "HYPALGESIC" wide //weight: 1
        $x_1_4 = "enamouredness" wide //weight: 1
        $x_1_5 = "Forhandlingspartnerne" wide //weight: 1
        $x_1_6 = "Indlemmede3" wide //weight: 1
        $x_1_7 = "agurketiders" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_VB_2147755076_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.VB!MTB"
        threat_id = "2147755076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "IU77ocBO8NAQod3vlFWpj5Yyeo0PB1136" wide //weight: 1
        $x_1_3 = "MsNP4YitUmAqMLCTT5VlHwh6" wide //weight: 1
        $x_1_4 = "WOIVepOhvRR8e78t0EfgxDKFRkVBLHVysl0r134" wide //weight: 1
        $x_1_5 = "IGSfJacgV65OZZmoful95VsUPU5xHnLv3KwJY184" wide //weight: 1
        $x_1_6 = "uMhrSXZNx1Nw94hqAv2iRnGNcZ9KxHa31" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SS_2147755378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SS!MTB"
        threat_id = "2147755378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {bb a2 3b a3 41 0f 75 f3 66 0f fd f0 66 0f 60 cb 66 0f f5 f9 0f eb e1 66 0f fe c3 0f d8 e1 31 1c 24 0f dc c9 66 0f 69 c6 66 0f 76 c5 0f dd c3 66 0f e5 d5 66 0f db fb 8f 04 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SS_2147755378_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SS!MTB"
        threat_id = "2147755378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 1d c0 00 00 00 [0-16] 83 fb 00 0f 84 [0-4] e9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 6e c0 0f 6e 0b 0f ef c1 51 [0-16] 0f 7e c1 88 c8 [0-16] 59}  //weight: 1, accuracy: Low
        $x_1_3 = {89 e0 83 c4 06 ff 28 e8 ?? ff ff ff c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SS_2147755378_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SS!MTB"
        threat_id = "2147755378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 34 0a 66 0f 69 de 66 0f 68 e2 66 0f 6b cc 66 0f 63 de 0f 6a c2 0f 67 da 0f 69 c8 66 0f 68 e3 66 0f 68 f6 0f 6a ed 0f 6b ef 0f 68 f3 81 f6 ?? ?? ?? ?? 66 0f 68 e8 0f 6b ca 0f 6a f5 0f 63 e2 0f 69 ee 0f 69 c9 0f 6b c0 0f 67 f9 66 0f 6a cc 66 0f 6b c8 0f 67 e3 0f 6a e8 0f 6b ef 0f 6a d7 0f 6b d9 89 34 08}  //weight: 5, accuracy: Low
        $x_5_2 = {0b 34 0a 0f 6b d7 66 0f 6b f6 66 0f 69 ce 66 0f 6a ce 0f 67 fe 66 0f 6b e9 0f 67 e7 0f 63 c4 66 0f 63 f8 81 f6 72 cd fb 07 0f 67 e1 0f 67 c9 66 0f 6b e0 0f 6a e0 0f 6a d0 66 0f 67 ea 0f 6a ff 0f 67 de 66 0f 63 c2 0f 6a e7 66 0f 63 d3 0f 68 d6 89 34 08}  //weight: 5, accuracy: High
        $x_5_3 = {0b 34 0a 0f 69 e1 0f 63 ce 66 0f 67 d0 0f 6b e4 66 0f 69 f1 0f 67 cd 0f 6a f3 0f 68 d3 66 0f 6b ec 0f 69 e7 0f 67 e9 66 0f 63 c5 66 0f 6b e7 0f 68 f9 81 f6 9d 42 28 f1 66 0f 6a d8 0f 6b ce 0f 6a e5 66 0f 6b ec 66 0f 6b e7 66 0f 6a eb 66 0f 68 d7 66 0f 67 e7 0f 69 d3 0f 6a fc 66 0f 6b eb 0f 6b f5 89 34 08}  //weight: 5, accuracy: High
        $x_1_4 = "Renteniveau7" wide //weight: 1
        $x_1_5 = "pericardiosymphysis" wide //weight: 1
        $x_1_6 = "Langmodighedens7" wide //weight: 1
        $x_1_7 = "Kommandonavns2" wide //weight: 1
        $x_1_8 = "Nonemission6" wide //weight: 1
        $x_1_9 = "Snversynedes7" wide //weight: 1
        $x_1_10 = "Vejafvandingsanlggene9" wide //weight: 1
        $x_1_11 = "Femhundredkroneseddelens" wide //weight: 1
        $x_1_12 = "Ingenirgerningers3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Guloader_DEA_2147755836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.DEA!MTB"
        threat_id = "2147755836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "WKA1Mxyo7oFg7S2TeFsrn7J562" wide //weight: 5
        $x_5_2 = "QTpAPYo9HQyDD232ZDyY9w9IF1FhJ225" wide //weight: 5
        $x_5_3 = "BpVioEKwVJFrit4wpgFclO2d6lqtlNHSExGA38" wide //weight: 5
        $x_1_4 = "ankerarmene" wide //weight: 1
        $x_1_5 = "Segmenterede5" wide //weight: 1
        $x_1_6 = "Forbind8" wide //weight: 1
        $x_1_7 = "Behovingly3" wide //weight: 1
        $x_1_8 = "micresthete" wide //weight: 1
        $x_5_9 = "rRicglfgvBTsQ8VHjphiOiI0THKmK216" wide //weight: 5
        $x_5_10 = "v2fo2wN1zVT4IUSycTLtP3poK161" wide //weight: 5
        $x_5_11 = "Q2otWSOJXLvLK265QQDL6sUPuMOUb33872" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Guloader_DEB_2147755927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.DEB!MTB"
        threat_id = "2147755927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 48 6c 19 eb 04 ff 00 00 00 c3 3d ?? ?? ?? ?? 75 04 64 a7 f6 78 3d 0d 00 81 f2 ?? ?? ?? ?? 3d ?? ?? ?? ?? 75 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_DEC_2147755928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.DEC!MTB"
        threat_id = "2147755928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sandstormenes" wide //weight: 1
        $x_1_2 = "Maskinudvalgs3" wide //weight: 1
        $x_1_3 = "Kvarterrapporternes8" wide //weight: 1
        $x_1_4 = "velyndernes" wide //weight: 1
        $x_2_5 = "Halvfjerdsaarsfdselsdagens" wide //weight: 2
        $x_2_6 = "DnxPPI3ZuxmY4lzJS0AVTnrFTY9mJ2uQ229" wide //weight: 2
        $x_2_7 = "Ekspositionsdelene3" wide //weight: 2
        $x_2_8 = "bjrgningsfartjet" wide //weight: 2
        $x_2_9 = "Olietankbekendtgrelse2" wide //weight: 2
        $x_2_10 = "Folketingsmedlemmernes6" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Guloader_DED_2147756630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.DED!MTB"
        threat_id = "2147756630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nOxdScXngE40JmKKrLkUvcjkr0gzFK43" wide //weight: 1
        $x_1_2 = "landbrugsdriftsbygningen" wide //weight: 1
        $x_1_3 = "K6JGwjI8ehO366lL9wyXu4t77" wide //weight: 1
        $x_1_4 = "wA3BiHG2kSC9px3JihTliYYN488" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Guloader_SA_2147757651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SA!MTB"
        threat_id = "2147757651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cockpitternes" wide //weight: 1
        $x_1_2 = "Sclerotoid6" wide //weight: 1
        $x_1_3 = "Forskningsprojekterne1" wide //weight: 1
        $x_1_4 = "tegneseriemestres" wide //weight: 1
        $x_1_5 = "Gennemarbejder" wide //weight: 1
        $x_1_6 = "flerbrugerinstallationen" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BH_2147757750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BH!MTB"
        threat_id = "2147757750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 04 81 34 0b ?? ?? ?? ?? [0-6] 83 f9 00 75 ?? 53 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {50 89 e0 83 c4 06 ff 28 e8 90 01 01 ff ff ff c3}  //weight: 1, accuracy: High
        $x_1_3 = {85 db 64 8b 1d c0 00 00 00 83 fb 00 74 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BH_2147757750_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BH!MTB"
        threat_id = "2147757750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Befrielsers\\allerinderste\\pelobatid" ascii //weight: 1
        $x_1_2 = "Siluroids%\\Poluphloisboic\\Stature\\Nicklavs\\Diphenoxylate.Nae" ascii //weight: 1
        $x_1_3 = "spedalsk\\Russens\\Biophotophone.dll" ascii //weight: 1
        $x_1_4 = "Software\\Nonregardance" ascii //weight: 1
        $x_1_5 = "Sknhedssansen.Ade" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AC_2147761824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AC!MTB"
        threat_id = "2147761824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a8 cb a1 72 d1 cb a1 72 86 93 a3 72 f9 09 a3 72 01 cc a1 72 0c cc a1 72 31 68 a4 72 29 19 a2 72 62 72 a4 72 88 be a0 72 ba 02 a3 72 41 09 a3 72}  //weight: 1, accuracy: High
        $x_1_2 = {20 e2 36 4b b8 42 4d 4b 00 00 10 75 d5 a3 02 42 2c f5 8d 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AC_2147761824_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AC!MTB"
        threat_id = "2147761824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "stafferet.men" ascii //weight: 2
        $x_2_2 = "preposing.for" ascii //weight: 2
        $x_2_3 = "reformismen.jpg" ascii //weight: 2
        $x_2_4 = "gdningsopbevaringerne.ini" ascii //weight: 2
        $x_2_5 = "boltrope.van" ascii //weight: 2
        $x_2_6 = "melodierne\\svejshundene" ascii //weight: 2
        $x_2_7 = "Concludent\\dknernes" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AR_2147762216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AR!MTB"
        threat_id = "2147762216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Colobium29\\Nomaden.dll" ascii //weight: 1
        $x_1_2 = "madlavningsskribenter\\lipotropy.ini" ascii //weight: 1
        $x_1_3 = "Recorporify\\enhjrnings.ini" ascii //weight: 1
        $x_1_4 = "Renommeers\\Tobaksaskes.bin" ascii //weight: 1
        $x_1_5 = "orgasmerne.ini" ascii //weight: 1
        $x_1_6 = "skovhugsten\\xiphopagous.htm" ascii //weight: 1
        $x_1_7 = "Rammeloves222.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AV_2147773835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AV!MTB"
        threat_id = "2147773835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c2 f5 94 08 00 89 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AV_2147773835_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AV!MTB"
        threat_id = "2147773835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 01 24 0a 00 a3}  //weight: 1, accuracy: High
        $x_1_2 = {01 44 24 10 8b 4c 24 10 33 cf 33 ce 2b d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AV_2147773835_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AV!MTB"
        threat_id = "2147773835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f8 6c 75 06 81 c1 1c a9 08 00 40 3d 0f 7e 49 00 7c}  //weight: 1, accuracy: High
        $x_1_2 = {01 04 24 b8 1c a9 08 00 01 04 24 8b 04 24 8a 14 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AV_2147773835_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AV!MTB"
        threat_id = "2147773835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f8 6c 75 06 81 c1 bc 2f 0a 00 40 3d 0f 7e 49 00 7c}  //weight: 1, accuracy: High
        $x_1_2 = {01 04 24 b8 bc 2f 0a 00 01 04 24 8b 04 24 8a 14 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RW_2147777557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RW!MTB"
        threat_id = "2147777557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Psychoanalyzed8" ascii //weight: 1
        $x_1_2 = "pP0Lxik0wuwigNhanoVgnNFo4Id788qm3Cnqi112" wide //weight: 1
        $x_1_3 = "Mc8afsFY0ZZxZfOwMQjlJ3QDsh74y766" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPI_2147796656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPI!MTB"
        threat_id = "2147796656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f ae e8 ff 31 [0-16] 5d [0-16] 81 f5 [0-16] 55 [0-16] 59 [0-16] 89 0c 37 [0-16] 4e [0-16] 4e [0-16] 4e [0-16] 4e 7d [0-16] 89 f9 [0-16] 51 [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPJ_2147796657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPJ!MTB"
        threat_id = "2147796657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f ae f0 ff 31 [0-16] 5d [0-16] 81 f5 [0-16] 55 [0-16] 59 [0-16] 89 0c 37 [0-16] 4e [0-16] 4e [0-16] 4e [0-16] 4e 7d [0-16] 89 f9 [0-16] 51 [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPL_2147796659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPL!MTB"
        threat_id = "2147796659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 0c 30 0f ae e8 de cb eb 4b}  //weight: 1, accuracy: High
        $x_1_2 = {9b 66 0f 61 d9 d8 d4 eb 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPL_2147796659_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPL!MTB"
        threat_id = "2147796659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d9 d0 33 04 32 [0-32] 35 [0-32] [0-16] 8b 1c 24 [0-32] 01 04 33 [0-32] 83 ee 04 0f 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPL_2147796659_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPL!MTB"
        threat_id = "2147796659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 2c 17 f7 c2 [0-32] [0-32] [0-16] 81 f5 [0-32] [0-32] [0-16] 01 2c 10 [0-32] [0-32] [0-32] 83 da 04 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RP_2147796695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RP!MTB"
        threat_id = "2147796695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\kraftudtryk\\kildekodepakke" ascii //weight: 1
        $x_1_2 = "brillanternes\\Microsoft\\Windows\\Factories\\Uninstall\\sukkerrterne\\metrorthosis" ascii //weight: 1
        $x_1_3 = "skitseprojekternes fragmentising orwell" wide //weight: 1
        $x_1_4 = "-\\gassers\\butikskdes.ini" ascii //weight: 1
        $x_1_5 = "nedblndingers.bou" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RP_2147796695_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RP!MTB"
        threat_id = "2147796695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\demigardebras\\ombrydningen.saa" ascii //weight: 10
        $x_1_2 = "%haemostatic%\\Overfreedom\\ledsage" ascii //weight: 1
        $x_1_3 = "styrketrningernes\\Uninstall\\subovarian" ascii //weight: 1
        $x_1_4 = "%afregningspris%\\Trkkrfterne\\protorthoptera" ascii //weight: 1
        $x_1_5 = "\\punktets.ini" ascii //weight: 1
        $x_1_6 = "\\anglikanere\\Litteratursgningsprocessernes230.mac" ascii //weight: 1
        $x_1_7 = "Udmugningsanlggene200\\hoverende\\stersskallens" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RP_2147796695_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RP!MTB"
        threat_id = "2147796695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\impolite\\slnggrebet\\Unregularized" wide //weight: 10
        $x_10_2 = "Aurigal\\semigranitic\\ambassaders" wide //weight: 10
        $x_10_3 = "%undercoloring%\\datamaternes\\preconizer.dat" wide //weight: 10
        $x_1_4 = "user-status-pending-symbolic.svg" wide //weight: 1
        $x_1_5 = "emoji-people-symbolic.svg" wide //weight: 1
        $x_1_6 = "starred-symbolic.svg" wide //weight: 1
        $x_10_7 = "symbolic.jpg" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RP_2147796695_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RP!MTB"
        threat_id = "2147796695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\fantomers\\Forcemeat141" wide //weight: 10
        $x_10_2 = "Software\\Buk\\oval" wide //weight: 10
        $x_10_3 = "sobersided\\factorised\\nonmelodiously" wide //weight: 10
        $x_1_4 = "\\braminernes.ini" wide //weight: 1
        $x_10_5 = "\\sengestolpes\\Yveregenskabernes.shr" wide //weight: 10
        $x_1_6 = "\\Dialogsystemet23.Uds" wide //weight: 1
        $x_10_7 = "\\feodaries\\Elds.kri" wide //weight: 10
        $x_1_8 = "Displeasedly246.dro" wide //weight: 1
        $x_1_9 = "Textman162.ink" wide //weight: 1
        $x_1_10 = "austral.yos" wide //weight: 1
        $x_1_11 = "ibrahims.smo" wide //weight: 1
        $x_1_12 = "lateness.gar" wide //weight: 1
        $x_1_13 = "lnindtgtens.rep" wide //weight: 1
        $x_1_14 = "patriarks.pra" wide //weight: 1
        $x_1_15 = "portepeerne.ste" wide //weight: 1
        $x_1_16 = "rullestol.rin" wide //weight: 1
        $x_1_17 = "shantyens.was" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPP_2147797357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPP!MTB"
        threat_id = "2147797357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 4a 4a 09 3c 01 de e0 de f7 eb 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPP_2147797357_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPP!MTB"
        threat_id = "2147797357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 1c 38 ff 45 38 ff 4d 38 fc 83 c7 04 ff 45 38 ff 4d 38 83 04 24 00 81 ff ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPP_2147797357_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPP!MTB"
        threat_id = "2147797357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f dc e5 ff 34 32 [0-32] [0-32] 81 34 24 [0-32] 8f 04 30 [0-32] 83 de [0-32] [0-32] 83 d6 ?? 0f 8d ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPP_2147797357_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPP!MTB"
        threat_id = "2147797357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hinduistisk\\Actinine\\Enpuklet\\Unbastardized" ascii //weight: 1
        $x_1_2 = "Unaccustomed\\Ninni" ascii //weight: 1
        $x_1_3 = "Software\\Gawks" ascii //weight: 1
        $x_1_4 = "Software\\udbud" ascii //weight: 1
        $x_1_5 = "dictyota\\Stiple" ascii //weight: 1
        $x_1_6 = "Vitalized\\Torvedage" ascii //weight: 1
        $x_1_7 = "Samtiden" ascii //weight: 1
        $x_1_8 = "Whipcracker" ascii //weight: 1
        $x_1_9 = "Sulphocyanate.Kol" ascii //weight: 1
        $x_1_10 = "Centralforeningers.mut" ascii //weight: 1
        $x_1_11 = "hklingen.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPP_2147797357_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPP!MTB"
        threat_id = "2147797357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lyskers.Mil" wide //weight: 1
        $x_1_2 = "Undlb.Aff32" wide //weight: 1
        $x_1_3 = "Besaaningens.dll" wide //weight: 1
        $x_1_4 = "Printermanual\\Cawquaw\\Caliphs2" wide //weight: 1
        $x_1_5 = "Software\\Spinoff\\Systemtast\\Navigeringernes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPQ_2147797358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPQ!MTB"
        threat_id = "2147797358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 66 31 0c 1f d8 e4 d8 d9 eb 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPQ_2147797358_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPQ!MTB"
        threat_id = "2147797358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 53 56 e8 00 00 00 00 5a 81 c2 ?? ?? 00 00 8d 9a ?? ?? 00 00 6b f6 00 69 f6 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 31 32 83 c2 04 39 da 72 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPQ_2147797358_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPQ!MTB"
        threat_id = "2147797358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dorsolum" ascii //weight: 1
        $x_1_2 = "Modstandsorganisationer" ascii //weight: 1
        $x_1_3 = "Afklinger.Tid" ascii //weight: 1
        $x_1_4 = "Astromeda.AER" ascii //weight: 1
        $x_1_5 = "Admitting\\Digressive\\Stalden.dll" ascii //weight: 1
        $x_1_6 = "Preinitiation\\Umaaleliges\\Earnestly86" ascii //weight: 1
        $x_1_7 = "Flippermaskines\\Grundskuddene.ECO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPQ_2147797358_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPQ!MTB"
        threat_id = "2147797358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ironbush.Ant" wide //weight: 1
        $x_1_2 = "Telegigant.ini" wide //weight: 1
        $x_1_3 = "Anociassociation.Fui" wide //weight: 1
        $x_1_4 = "Uninstall\\coroa" wide //weight: 1
        $x_1_5 = "tapeterne\\Dmpe\\Universalisers" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPQ_2147797358_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPQ!MTB"
        threat_id = "2147797358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fotocelle\\Unsurgically" wide //weight: 1
        $x_1_2 = "Arbejdsorganiseringens115.lnk" wide //weight: 1
        $x_1_3 = "Anencephalous.Non" wide //weight: 1
        $x_1_4 = "Software\\Outproduce\\Wienerstigernes\\Unwistful\\Forretningsmssig" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_C_2147797900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.C!MTB"
        threat_id = "2147797900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "inkasseringens.ini" ascii //weight: 2
        $x_2_2 = "guslee.lta" ascii //weight: 2
        $x_2_3 = "straksafskrivningerne.sak" ascii //weight: 2
        $x_2_4 = "skatteprocents\\heldterningens" ascii //weight: 2
        $x_2_5 = "minirobot.uni" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_C_2147797900_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.C!MTB"
        threat_id = "2147797900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FLLESKLUBBERNES" wide //weight: 1
        $x_1_2 = "Bewilderment1" wide //weight: 1
        $x_1_3 = "Hardedge" wide //weight: 1
        $x_1_4 = "Cofeoffee" wide //weight: 1
        $x_1_5 = "Theoremic" wide //weight: 1
        $x_1_6 = "honningernes" wide //weight: 1
        $x_1_7 = "UNCOUNSELLABLE" wide //weight: 1
        $x_1_8 = "hypertrophous" wide //weight: 1
        $x_1_9 = "skjtefrets" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_C_2147797900_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.C!MTB"
        threat_id = "2147797900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gibson Disluster Reservationsdatoens Synectically" wide //weight: 1
        $x_1_2 = "Coadjutement Tekststumpen attraavrdigheds" wide //weight: 1
        $x_1_3 = "Crocko skovkant Attice Glimtede" wide //weight: 1
        $x_1_4 = "EPISKOPETS Operationsbeskrivelses" wide //weight: 1
        $x_1_5 = "Nonhouseholder Underarmsmuskelens" wide //weight: 1
        $x_1_6 = "spermacettets potoroos Lderveste Zeuglodont" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_B_2147799407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.B!MTB"
        threat_id = "2147799407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Dukkeansigt.Pre" ascii //weight: 2
        $x_2_2 = "christianshavnerne.deh" ascii //weight: 2
        $x_2_3 = "Unrhymed.adi" ascii //weight: 2
        $x_2_4 = "ekstraprogrammer\\foryngelseskur" ascii //weight: 2
        $x_2_5 = "snorebroderier\\Celeste" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_B_2147799407_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.B!MTB"
        threat_id = "2147799407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Curlincompliancy3" wide //weight: 1
        $x_1_2 = "Hoffrdiginquisiturie" wide //weight: 1
        $x_1_3 = "Hyperimmunizinggrifler" wide //weight: 1
        $x_1_4 = "regningsopgavernes" wide //weight: 1
        $x_1_5 = "vurderingsgrundlag" wide //weight: 1
        $x_1_6 = "Grundskyldspromille6" wide //weight: 1
        $x_1_7 = "kbenhavnsomraadet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_B_2147799407_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.B!MTB"
        threat_id = "2147799407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Julemrker Rederiet Airtight" wide //weight: 1
        $x_1_2 = "Harlequinery Alto Misgauge" wide //weight: 1
        $x_1_3 = "Skolepligter Armeernes" wide //weight: 1
        $x_1_4 = "SKOSVRTENS Pilhenvisninger Anglicanism2" wide //weight: 1
        $x_1_5 = "Vitalists Snegle" wide //weight: 1
        $x_1_6 = "Intergalactic Butiksstruktur Unfilched43" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPZ_2147799545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPZ!MTB"
        threat_id = "2147799545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gudda91" ascii //weight: 1
        $x_1_2 = "Ukunstnerisk71" ascii //weight: 1
        $x_1_3 = "Blomsterkostes51" ascii //weight: 1
        $x_1_4 = "Marekanite1" ascii //weight: 1
        $x_1_5 = "RDVINSGLASSENES1" ascii //weight: 1
        $x_1_6 = "hanks" ascii //weight: 1
        $x_1_7 = "221217115151Z0" ascii //weight: 1
        $x_1_8 = "310106000000Z0H1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPZ_2147799545_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPZ!MTB"
        threat_id = "2147799545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 0c 1e 81 [0-32] [0-32] 81 f1 [0-32] [0-16] 31 0c 1f [0-32] 81 c3 [0-16] [0-16] 81 eb [0-16] [0-32] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPZ_2147799545_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPZ!MTB"
        threat_id = "2147799545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Corpora220.Fil" ascii //weight: 1
        $x_1_2 = "bestningsmedlem.cha" ascii //weight: 1
        $x_1_3 = "pollinosis.Ktt" ascii //weight: 1
        $x_1_4 = "unswayableness" ascii //weight: 1
        $x_1_5 = "sidehngte.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPZ_2147799545_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPZ!MTB"
        threat_id = "2147799545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Madmoderen.dll" ascii //weight: 1
        $x_1_2 = "Cabmen\\afhudet" ascii //weight: 1
        $x_1_3 = "worthwhileness" ascii //weight: 1
        $x_1_4 = "overjegers" ascii //weight: 1
        $x_1_5 = "Sukkerkuglernes201.her" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPZ_2147799545_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPZ!MTB"
        threat_id = "2147799545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "footies.rwa" ascii //weight: 1
        $x_1_2 = "nonchargeable.fal" ascii //weight: 1
        $x_1_3 = "silkepapirs.gul" ascii //weight: 1
        $x_1_4 = "revalideringscentres.bru" ascii //weight: 1
        $x_1_5 = "Suzannah" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPZ_2147799545_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPZ!MTB"
        threat_id = "2147799545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tennisens\\nonmalleabness" ascii //weight: 1
        $x_1_2 = "unimmortalised" ascii //weight: 1
        $x_1_3 = "lethality\\diassene" ascii //weight: 1
        $x_1_4 = "regripped\\lippings.wit" ascii //weight: 1
        $x_1_5 = "kvadrupel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPZ_2147799545_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPZ!MTB"
        threat_id = "2147799545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regionplanretningslinjer" ascii //weight: 1
        $x_1_2 = "slethvarrers" ascii //weight: 1
        $x_1_3 = "gynandromorphy" ascii //weight: 1
        $x_1_4 = "sekretariatsmedarbejderen" ascii //weight: 1
        $x_1_5 = "Taastrupgaard230" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPZ_2147799545_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPZ!MTB"
        threat_id = "2147799545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "overwithered.ver" ascii //weight: 10
        $x_1_2 = "farvehandlens.met" ascii //weight: 1
        $x_1_3 = "Cardinalship\\indtrngende.til" ascii //weight: 1
        $x_1_4 = "Stormende\\Pejlet184" ascii //weight: 1
        $x_1_5 = "immunologis.Byg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPZ_2147799545_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPZ!MTB"
        threat_id = "2147799545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "delayer\\Hortensiaerne" ascii //weight: 1
        $x_1_2 = "rhesuspositive\\Uninstall\\oktoberens" ascii //weight: 1
        $x_1_3 = "Serriedness\\Uninstall\\erinaceus" ascii //weight: 1
        $x_1_4 = "Gtesengenes" ascii //weight: 1
        $x_1_5 = "Brandskaders138" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPZ_2147799545_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPZ!MTB"
        threat_id = "2147799545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spaniels\\Cholecystectomized93\\abluvion" wide //weight: 1
        $x_1_2 = "pippendes.ini" wide //weight: 1
        $x_1_3 = "CurrentVersion\\Uninstall\\suggestivitets" wide //weight: 1
        $x_1_4 = "Software\\DEMARCATORS\\PROTEACEAE" wide //weight: 1
        $x_1_5 = "Vtgdi3lA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_E_2147805175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.E!MTB"
        threat_id = "2147805175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "garantien" wide //weight: 1
        $x_1_2 = "ACHOO" wide //weight: 1
        $x_1_3 = "Teknologiseringers2" wide //weight: 1
        $x_1_4 = "COINVENTORS" wide //weight: 1
        $x_1_5 = "Identiv" wide //weight: 1
        $x_1_6 = "FYRRETYVENDEDELES" ascii //weight: 1
        $x_1_7 = "Ureterorrhaphy9" ascii //weight: 1
        $x_1_8 = "Hegnstraadenes2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_D_2147805626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.D!MTB"
        threat_id = "2147805626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "STYRETABELLER" wide //weight: 1
        $x_1_2 = "Tvivlsomst9" wide //weight: 1
        $x_1_3 = "Koaguleringerne7" wide //weight: 1
        $x_1_4 = "ministerstormens" wide //weight: 1
        $x_1_5 = "Frigrelsesmidlerne5" wide //weight: 1
        $x_1_6 = "Calelectricity" wide //weight: 1
        $x_1_7 = "skuddermudderets" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BEB_2147805838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BEB!MTB"
        threat_id = "2147805838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Afkortningen7" wide //weight: 1
        $x_1_2 = "spyendesstobballs" wide //weight: 1
        $x_1_3 = "Sucrosetautologiseskeytingw6" wide //weight: 1
        $x_1_4 = "Intervaryingvictoriastrosbe9" wide //weight: 1
        $x_1_5 = "GURUSREEXCHANGESNYTTEVIRKNI" wide //weight: 1
        $x_1_6 = "TALENTFULDERES" wide //weight: 1
        $x_1_7 = "ANDREWARTHA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPN_2147805919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPN!MTB"
        threat_id = "2147805919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 1c 0e 81 f9 bd 00 00 00 81 fa 98 00 00 00 09 1c 08 83 fa 40 81 f9 cc 00 00 00 31 3c 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPN_2147805919_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPN!MTB"
        threat_id = "2147805919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 55 08 66 0f 66 ca 0f d8 c3 0f 6b fc eb 11}  //weight: 1, accuracy: High
        $x_1_2 = {31 0c 06 66 0f 69 c6 9b db e2 66 0f 69 cf eb 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPN_2147805919_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPN!MTB"
        threat_id = "2147805919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\nonreasoning\\dagsaktuelt" wide //weight: 10
        $x_1_2 = "Bikuber11.com" wide //weight: 1
        $x_1_3 = "Forlems.bar" wide //weight: 1
        $x_1_4 = "Refers.ini" wide //weight: 1
        $x_1_5 = "Renownless.ini" wide //weight: 1
        $x_1_6 = "Sundhedstegnene.txt" wide //weight: 1
        $x_1_7 = "Uncharacterized.ini" wide //weight: 1
        $x_1_8 = "skatteaarene.txt" wide //weight: 1
        $x_1_9 = "nsis.sf.net/NSIS_Error" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPN_2147805919_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPN!MTB"
        threat_id = "2147805919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "glumaceous.lnk" wide //weight: 1
        $x_1_2 = "Shetlandsponyens107.exe" wide //weight: 1
        $x_1_3 = "Arkivkopier114.ini" wide //weight: 1
        $x_1_4 = "hundehusene.exe" wide //weight: 1
        $x_1_5 = "TJERI.lnk" wide //weight: 1
        $x_1_6 = "DRIFTIGSTES.txt" wide //weight: 1
        $x_1_7 = "PUMMELLED.bmp" wide //weight: 1
        $x_1_8 = "Rdklver\\Talliniernes140" wide //weight: 1
        $x_1_9 = "forklders\\Subpectinate213" wide //weight: 1
        $x_1_10 = "Uninstall\\foringerne" wide //weight: 1
        $x_1_11 = "Indfjelsers143" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPO_2147805920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPO!MTB"
        threat_id = "2147805920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 1c 10 83 ff 2e 83 fa 43 9b db e2 66 0f fa fa db e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPO_2147805920_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPO!MTB"
        threat_id = "2147805920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d2 66 0f d8 c4 0f 69 cd d9 e1 eb 19}  //weight: 1, accuracy: High
        $x_1_2 = {09 14 08 66 0f 74 f8 66 0f eb ea d9 c9 d8 d7 eb 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPO_2147805920_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPO!MTB"
        threat_id = "2147805920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WOLFBERRIES.exe" wide //weight: 1
        $x_1_2 = "crocketing.dll" wide //weight: 1
        $x_1_3 = "CALCIFUGAL.lnk" wide //weight: 1
        $x_1_4 = "Funned241.exe" wide //weight: 1
        $x_1_5 = "clretwrc.dll" wide //weight: 1
        $x_1_6 = "Forurening132" wide //weight: 1
        $x_1_7 = "Vigdi3lAlloc" wide //weight: 1
        $x_1_8 = "DeleteDC" wide //weight: 1
        $x_1_9 = "GetFileSecurityA" wide //weight: 1
        $x_1_10 = "GetCaretBlinkTime" wide //weight: 1
        $x_1_11 = "CryptDestroyHash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPR_2147808065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPR!MTB"
        threat_id = "2147808065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 26 26 26 26 26 26 26 26 26 26 66 31 0c 1f d8 cc db e2 eb 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPR_2147808065_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPR!MTB"
        threat_id = "2147808065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d f0 73 27 8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPR_2147808065_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPR!MTB"
        threat_id = "2147808065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Loney86\\Varengan" wide //weight: 1
        $x_1_2 = "Fejlskuddene.Kun129" wide //weight: 1
        $x_1_3 = "Maalestok\\Flyings.Ord" wide //weight: 1
        $x_1_4 = "Sengetppet.Low" wide //weight: 1
        $x_1_5 = "Obbenite.Adv" wide //weight: 1
        $x_1_6 = "Ravnemoderens35.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPS_2147808066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPS!MTB"
        threat_id = "2147808066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 85 c9 31 1c 08 66 85 c0 83 c1 04 de e8 eb 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPT_2147808340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPT!MTB"
        threat_id = "2147808340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 2c 1a 90 9b 31 2c 18 9b 90 81 34 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPT_2147808340_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPT!MTB"
        threat_id = "2147808340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fidele\\Whiskyens" ascii //weight: 1
        $x_1_2 = "Excurvature\\Scapulare.dep" ascii //weight: 1
        $x_1_3 = "Nubigenous\\Noncrystallisable.Kik" ascii //weight: 1
        $x_1_4 = "Ottecylindret\\Shampooers54.Sva" ascii //weight: 1
        $x_1_5 = "Pneumonectomy" ascii //weight: 1
        $x_1_6 = "Software\\Rappini200\\Klageretterne" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPU_2147808341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPU!MTB"
        threat_id = "2147808341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 5d 00 3d bb 00 00 00 83 fe 2d}  //weight: 1, accuracy: High
        $x_1_2 = {81 fa e9 00 00 00 81 f9 a2 00 00 00 01 1c 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPU_2147808341_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPU!MTB"
        threat_id = "2147808341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\aktionsgruppernes" ascii //weight: 1
        $x_1_2 = "borgerligstes\\Felinophile" ascii //weight: 1
        $x_1_3 = "KILLINGETUNGERNES\\Athenaeums.ops" ascii //weight: 1
        $x_1_4 = "Bilmodel\\superpartient\\Candide" ascii //weight: 1
        $x_1_5 = "Software\\Stymphalus98" ascii //weight: 1
        $x_1_6 = "Vestliges\\Preadolescent244" ascii //weight: 1
        $x_1_7 = "phocoena" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPV_2147808342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPV!MTB"
        threat_id = "2147808342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 1c 08 d9 fd 0f ae e8 eb 2d}  //weight: 1, accuracy: High
        $x_1_2 = {39 c6 66 0f fd c7 d9 fd eb 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SF_2147811104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SF!MTB"
        threat_id = "2147811104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OhxGFWabiTZ16PpkJAvcXCtkMMlSJiZG44" wide //weight: 2
        $x_1_2 = "PGiys02vlm4ldIlOhumWDsFDUKEjbeyS5132" wide //weight: 1
        $x_1_3 = "za05LQoSLX2d5bWYH2FeRWXzrGzyiZkvZttyKLcQ161" wide //weight: 1
        $x_1_4 = "yKxP1mX23r105" wide //weight: 1
        $x_1_5 = "MUoY6c3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Guloader_SIBU4_2147813522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBU4!MTB"
        threat_id = "2147813522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GiantDock" wide //weight: 1
        $x_1_2 = {cd 81 34 1a ?? ?? ?? ?? [0-48] 43 [0-53] 43 [0-64] 43 [0-37] 43 [0-53] 81 fb ?? ?? ?? ?? [0-16] eb 20 [0-37] 0f 85 ?? ?? ?? ?? [0-170] 81 2e ?? ?? ?? ?? [0-64] 81 36 ?? ?? ?? ?? [0-181] ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SIBU5_2147813610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBU5!MTB"
        threat_id = "2147813610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Kommandolinjernes" ascii //weight: 1
        $x_1_2 = {89 c7 0f fd fa c2 02 be ?? ?? ?? ?? 5c 02 31 d2 48 02 31 c9 76 02 33 0c 16 dd 02 81 f1 ?? ?? ?? ?? 45 02 31 0c 17 c0 02 81 c2 ?? ?? ?? ?? ec 01 81 ea ?? ?? ?? ?? e1 02 81 fa ?? ?? ?? ?? [0-90] 0f 85 ?? ?? ?? ?? a6 02 59 59 02 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SIBU6_2147813651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBU6!MTB"
        threat_id = "2147813651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f8 81 34 1a ?? ?? ?? ?? [0-64] 43 [0-48] 43 [0-42] 43 [0-48] 43 [0-53] 81 fb b0 0d 01 00 [0-42] 0f 85 a9 fe ff ff b5 01 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SIBU7_2147813652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBU7!MTB"
        threat_id = "2147813652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 81 34 07 ?? ?? ?? ?? [0-170] 83 c0 04 [0-176] 3d 74 1a 01 00 [0-48] 0f 85 ca fd ff ff [0-170] ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SIBU8_2147813653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBU8!MTB"
        threat_id = "2147813653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 81 34 07 ?? ?? ?? ?? [0-160] 83 c0 04 [0-154] 3d ?? ?? ?? ?? [0-48] 0f 85 ?? ?? ?? ?? [0-149] ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SIBU9_2147813654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBU9!MTB"
        threat_id = "2147813654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 81 34 07 b8 d6 f9 ac [0-170] 83 c0 04 [0-160] 3d 0c 15 01 00 [0-53] 0f 85 d0 fd ff ff [0-154] ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SIBU10_2147813655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBU10!MTB"
        threat_id = "2147813655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {71 81 34 07 ?? ?? ?? ?? [0-172] 83 c0 04 [0-160] 3d 74 18 01 00 [0-42] 0f 85 e8 fd ff ff [0-149] ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SIBU11_2147813656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBU11!MTB"
        threat_id = "2147813656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 81 34 07 ?? ?? ?? ?? [0-144] 83 c0 04 [0-154] 3d ?? ?? ?? ?? [0-42] 0f 85 ?? ?? ?? ?? [0-138] ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SIBU12_2147813657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBU12!MTB"
        threat_id = "2147813657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 81 34 07 ?? ?? ?? ?? [0-58] 83 c0 00 [0-128] 83 c0 04 [0-157] 3d ?? ?? ?? ?? [0-53] 0f 85 ?? ?? ?? ?? [0-149] ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SIBU13_2147813658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBU13!MTB"
        threat_id = "2147813658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 81 34 07 ?? ?? ?? ?? [0-160] 83 c0 04 [0-106] 83 c1 00 [0-48] 3d ?? ?? ?? ?? [0-48] 0f 85 ?? ?? ?? ?? [0-186] ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SIBV_2147815037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBV!MTB"
        threat_id = "2147815037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HIDEN_EXE" ascii //weight: 1
        $x_1_2 = {ba 01 00 00 00 a1 ?? ?? ?? ?? 8b 38 ff 57 0c 8b 85 ?? ?? ?? ?? 8b 16 0f b6 7c 10 ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba 00 01 00 00 2b d0 52 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5a 92 8b ca 99 f7 f9 03 fa 8b d7 8d 85 ?? ?? ?? ?? e8 e4 6b fa ff 8b 95 06 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 06 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPW_2147815686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPW!MTB"
        threat_id = "2147815686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 3c 01 d8 c1 d9 f1 eb 19 9e 76 d4 70 93 93 93}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPW_2147815686_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPW!MTB"
        threat_id = "2147815686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 78 38 30 30 30 30 30 30 30 00 56 69 72 74 75 00 61 6c 41 6c 00 03 82 80 00 36 30 00 69 6c 65 00 6c 6f 63 45 00 37 31 30 00 31 33 31 31 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPX_2147815687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPX!MTB"
        threat_id = "2147815687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 1c 10 d9 f2 dd e1 0f 6f df 0f e8 fc eb 2b 26 0b 1e 01 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPX_2147815687_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPX!MTB"
        threat_id = "2147815687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Colessors\\SWIFTNESS\\Gathered\\Sandvaaneren.lnk" ascii //weight: 1
        $x_1_2 = "Unreportorial.BRN" ascii //weight: 1
        $x_1_3 = "Otariidae.Hyp" ascii //weight: 1
        $x_1_4 = "indholdsmssige.FOR" ascii //weight: 1
        $x_1_5 = "Unbedinned" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPX_2147815687_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPX!MTB"
        threat_id = "2147815687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Bortviser\\Forskningsmilj\\Stolelike" ascii //weight: 1
        $x_1_2 = "Maskinskriverskernes" ascii //weight: 1
        $x_1_3 = "Goodtemperedness\\Rendets" ascii //weight: 1
        $x_1_4 = "Forskelligt" ascii //weight: 1
        $x_1_5 = "Digterkollektivets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPX_2147815687_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPX!MTB"
        threat_id = "2147815687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Malinche\\Fortabe" wide //weight: 1
        $x_1_2 = "Bianca\\Vmmelige\\Aandeliggr" wide //weight: 1
        $x_1_3 = "Uninstall\\Proletarian\\Wich60\\Alfaki" wide //weight: 1
        $x_1_4 = "micromeritic.ini" wide //weight: 1
        $x_1_5 = "Spearsmen.Lea" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SIBM13_2147817702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SIBM13!MTB"
        threat_id = "2147817702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 6e cb [0-10] 50 [0-10] 31 f6 [0-10] ff 34 30 [0-10] 5b [0-10] 66 0f 6e eb [0-10] [0-10] 66 0f ef e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPM_2147826306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPM!MTB"
        threat_id = "2147826306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Analerotikken\\cay.htm" ascii //weight: 1
        $x_1_2 = "affldigst\\flyman.gif" ascii //weight: 1
        $x_1_3 = "Kyststrkninger.zip" ascii //weight: 1
        $x_1_4 = "skolegaarde.txt" ascii //weight: 1
        $x_10_5 = "torulas.zip" ascii //weight: 10
        $x_1_6 = "smudsets\\doubleheartedness.bin" ascii //weight: 1
        $x_1_7 = "Cataleptize\\hksaksens.ini" ascii //weight: 1
        $x_1_8 = "furfur.lnk" ascii //weight: 1
        $x_1_9 = "humdrumminess\\rdvines.zip" ascii //weight: 1
        $x_10_10 = "oxyderingerne\\kalkenes\\Svederemmenes" ascii //weight: 10
        $x_1_11 = "Indtappes.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPM_2147826306_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPM!MTB"
        threat_id = "2147826306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "monkbird.ROS" wide //weight: 1
        $x_1_2 = "Penalhuses.cel" wide //weight: 1
        $x_1_3 = "midsommerens.Let" wide //weight: 1
        $x_1_4 = "Equitist.lnk" wide //weight: 1
        $x_1_5 = "uheldigvise.Ame" wide //weight: 1
        $x_1_6 = "Rattenes136" wide //weight: 1
        $x_1_7 = "Ricebird138" wide //weight: 1
        $x_1_8 = "Software\\Addictions" wide //weight: 1
        $x_1_9 = "Uninstall\\deflowering" wide //weight: 1
        $x_1_10 = "Kildesprogets\\Fluviation30" wide //weight: 1
        $x_1_11 = "Haunchless\\gladiator" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASH_2147826862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASH!MTB"
        threat_id = "2147826862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "longhouse\\Habilimentation226.ini" ascii //weight: 1
        $x_1_2 = "Uagtsommes\\Eftermiddagsmaaltiders\\smudse" ascii //weight: 1
        $x_1_3 = "sjldenheder\\Syrebadets.tor" ascii //weight: 1
        $x_1_4 = "resfornrmendes\\Printerkommando.vel" ascii //weight: 1
        $x_1_5 = "gteskabssagen\\Afkristnendes.dll" ascii //weight: 1
        $x_1_6 = "Totalsaneringen242.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASH_2147826862_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASH!MTB"
        threat_id = "2147826862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ARMOURY CRATE eGPU Product.exe" ascii //weight: 1
        $x_1_2 = "gnome-power-manager-symbolic.svg" ascii //weight: 1
        $x_1_3 = "CurrentVersion\\Uninstall\\monopneumoa" ascii //weight: 1
        $x_1_4 = "Uninstall\\Bedmates\\Tropikfronten" ascii //weight: 1
        $x_1_5 = "Datidsformens\\OFFENTLIGHEDENS.ini" ascii //weight: 1
        $x_1_6 = "HEX32.DLL" ascii //weight: 1
        $x_1_7 = "Katalogbestilling\\Gentlest7\\Stttevokalers.lnk" ascii //weight: 1
        $x_1_8 = "Vindinger\\Evadtrenes.dll" ascii //weight: 1
        $x_1_9 = "afstumpning\\Spildeolie.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPY_2147827085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPY!MTB"
        threat_id = "2147827085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Ribstrikkedes\\Waspiest" wide //weight: 1
        $x_1_2 = "Athelia\\Hjerneskadedes\\startparameterets\\Gripey.Mar" wide //weight: 1
        $x_1_3 = "CurrentVersion\\Uninstall\\UCIVILISEREDE\\betjentformndene" wide //weight: 1
        $x_1_4 = "Ramsey83.Til" wide //weight: 1
        $x_1_5 = "Vagogram\\KABAYA\\Cocuisa\\Affaldsrummet.Akt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RS_2147833667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RS!MTB"
        threat_id = "2147833667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_2 = "InitiateShutdownW" ascii //weight: 1
        $x_2_3 = "dolkede Maanederne Derfra" wide //weight: 2
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RR_2147833669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RR!MTB"
        threat_id = "2147833669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_2 = "InitiateShutdownW" ascii //weight: 1
        $x_2_3 = "Frenatae Bioenergi Rechabitism" wide //weight: 2
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AJ_2147836731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AJ!MTB"
        threat_id = "2147836731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Forsvorne130\\Tisss\\Afdkning.dll" ascii //weight: 1
        $x_1_2 = "Bajs\\Tegningsfristerne\\Cerograph.dll" ascii //weight: 1
        $x_1_3 = "Forbrugerkroner\\Ananism.Cle" ascii //weight: 1
        $x_1_4 = "Ethnarchs\\Planlgningsbestemmelsen.hje" ascii //weight: 1
        $x_1_5 = "Basisuddannelses\\Cantharides\\Bandaging.ini" ascii //weight: 1
        $x_1_6 = "Morice\\Farvemodulet\\aandedragets\\Equalise.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AJ_2147836731_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AJ!MTB"
        threat_id = "2147836731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ddelighedsstatistikkerne.ini" wide //weight: 1
        $x_1_2 = "autovaskeanlggenes\\Mink176" wide //weight: 1
        $x_1_3 = "Software\\Indspilningers\\afkvistninger" wide //weight: 1
        $x_1_4 = "Erstatningsreglernes.ini" wide //weight: 1
        $x_1_5 = "prikkendes\\Superpreparation182" wide //weight: 1
        $x_1_6 = "Bugspytkirtelens.log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPQQ_2147837799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPQQ!MTB"
        threat_id = "2147837799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "metalspyds Grover" wide //weight: 1
        $x_1_2 = "Symbolology1*0(" ascii //weight: 1
        $x_1_3 = "Seasnail@Nonvascularly34.Bi1%0#" ascii //weight: 1
        $x_1_4 = "Unidirection Macroaggregate 1" ascii //weight: 1
        $x_1_5 = "pediatric Cementeringen.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SMTK_2147839717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SMTK!MTB"
        threat_id = "2147839717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 8a 88 00 c0 [0-2] 00 88 4d ff 8b 55 d8 03 55 f0 8a 02 88 45 fe 0f b6 4d ff c1 f9 03 0f b6 55 ff c1 e2 05 0b ca 0f b6 45 fe 33 c8 8b 55 f8 88 8a 00 c0 [0-2] 00 8b 45 f0 83 c0 01 99 b9 0d 00 00 00 f7 f9 89 55 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPH_2147840589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPH!MTB"
        threat_id = "2147840589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "121"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "cat -raw '" wide //weight: 10
        $x_1_2 = "powershell.exe" wide //weight: 1
        $x_100_3 = "\\Tekstbehandlingsdokumenter\\" wide //weight: 100
        $x_10_4 = {2e 00 73 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-12] 2c 00 33 00 29 00 3b 00 2e 00 24 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RPH_2147840589_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RPH!MTB"
        threat_id = "2147840589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pleurosaurus obfuscates" wide //weight: 1
        $x_1_2 = "mangler bronchia bedrevne" wide //weight: 1
        $x_1_3 = "privatbil efterhaandsoplysning" wide //weight: 1
        $x_5_4 = "supraocular tailorizes.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPQD_2147840678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPQD!MTB"
        threat_id = "2147840678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Adresselisten1" ascii //weight: 1
        $x_1_2 = "campussens@Suffix.dd1" ascii //weight: 1
        $x_1_3 = "Corrade Animadversional 1" ascii //weight: 1
        $x_1_4 = "Adresselisten0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPQS_2147840808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPQS!MTB"
        threat_id = "2147840808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Revisits@Totaliteten.Fri1 0" ascii //weight: 1
        $x_1_2 = "Tauromachian Tsenaales 1" ascii //weight: 1
        $x_1_3 = "Prothetely1'0%" ascii //weight: 1
        $x_1_4 = "Prothetely0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPL_2147842914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPL!MTB"
        threat_id = "2147842914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Unsqueamishness1" ascii //weight: 1
        $x_1_2 = "Sistence Tanan Waker 1" ascii //weight: 1
        $x_1_3 = "Annlils@Stences.Ve0" ascii //weight: 1
        $x_1_4 = "Annlils@Stences.Ve" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPLU_2147845261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPLU!MTB"
        threat_id = "2147845261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "besselian.Fri" ascii //weight: 1
        $x_1_2 = "Psalmed.ini" ascii //weight: 1
        $x_1_3 = "Anagogy.dll" ascii //weight: 1
        $x_1_4 = "Skattedepartementet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SRS_2147847010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SRS!MTB"
        threat_id = "2147847010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Matrikeldirektoraters.ini" ascii //weight: 1
        $x_1_2 = "Mrklagdes.Una" ascii //weight: 1
        $x_1_3 = "Barhovedet150" ascii //weight: 1
        $x_1_4 = "Skbnetimens" ascii //weight: 1
        $x_1_5 = "Stjforholds" ascii //weight: 1
        $x_1_6 = "Stersernes.fra" ascii //weight: 1
        $x_1_7 = "\\Uncolourables\\Druelighed.Sam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_XP_2147847923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.XP!MTB"
        threat_id = "2147847923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Overenskomstansttelses" ascii //weight: 1
        $x_1_2 = "Prologklausuler" ascii //weight: 1
        $x_1_3 = "Elektroingenirerne" ascii //weight: 1
        $x_1_4 = "Kursusplanens\\Laceworker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BI_2147848144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BI!MTB"
        threat_id = "2147848144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Eroticized\\Regelmssigst\\Kolportrernes77\\Claudianus.Kns" wide //weight: 1
        $x_1_2 = "Knsrollebevidste\\Synonymous\\Productus\\Synshmmede.ini" wide //weight: 1
        $x_1_3 = "Noncondensation\\Ceres\\Plisserede.dll" wide //weight: 1
        $x_1_4 = "Apotropaism\\Raaddent\\augmentedly\\Endorsation.Mal" wide //weight: 1
        $x_1_5 = "Autopolyploid\\Fremavles\\Snaskendes129.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BJ_2147848145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BJ!MTB"
        threat_id = "2147848145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chiffonen\\Brownnoser65\\Tarpaper\\Merkantiliseringers.ini" ascii //weight: 1
        $x_1_2 = "Afrejste235\\tetartocone\\Libeling\\Hydramnion.Gru" ascii //weight: 1
        $x_1_3 = "Hematose\\Melanis\\Spektralanalysen\\Unurbane.ini" ascii //weight: 1
        $x_1_4 = "Mastodont\\Birkes\\Romantisme\\Landholdings.Goo" ascii //weight: 1
        $x_1_5 = "Peepul\\Cytogenetikkens\\Opgaveforloebet\\Confessorship" ascii //weight: 1
        $x_1_6 = "Unstagily\\Minstrels\\Rhapontin\\Disguisal.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BJ_2147848145_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BJ!MTB"
        threat_id = "2147848145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Ravrret\\Methodless\\Troskabslfter\\Stricken" wide //weight: 1
        $x_1_2 = "Software\\Svinghjulsarm\\Snitmnstrets\\Thienone" wide //weight: 1
        $x_1_3 = "Unhelmed\\phys.ini" wide //weight: 1
        $x_1_4 = "Penance.dll" wide //weight: 1
        $x_1_5 = "Raketvrnssystemer Chabasite" wide //weight: 1
        $x_1_6 = "Software\\Nonvisibilities\\Bradyseismal\\Afsejlingens" ascii //weight: 1
        $x_1_7 = "Yngledes%\\Kautionens\\Velchanos.Kom" ascii //weight: 1
        $x_1_8 = "CurrentVersion\\Uninstall\\Sundrymen\\Kartoteksstyringen\\Paanaer\\Hoerte" ascii //weight: 1
        $x_1_9 = "Software\\Chaplins" ascii //weight: 1
        $x_1_10 = "Afgivelsernes Persistence Tarteletters" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Guloader_BP_2147849508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BP!MTB"
        threat_id = "2147849508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Crouton\\Indvindingernes.Par" ascii //weight: 1
        $x_1_2 = "Hvidevarer\\Felice\\Quatuor\\Carbonatation.shu" ascii //weight: 1
        $x_1_3 = "Software\\Exporters\\Scybala178" ascii //weight: 1
        $x_1_4 = "Overstrmmendes250\\Ekskluder\\Coocoo.Sor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BQ_2147850248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BQ!MTB"
        threat_id = "2147850248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sonicators\\falsifikationen\\decal\\lectica.oed" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\solskinstage\\overserene" ascii //weight: 1
        $x_1_3 = "solenostomid\\telesatellitters.Cop" ascii //weight: 1
        $x_1_4 = "Software\\Bysvalerne\\preunderstanding" ascii //weight: 1
        $x_1_5 = "requisitioned\\aritmetiker\\antitumour\\bilateral.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BR_2147850265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BR!MTB"
        threat_id = "2147850265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Crossbite\\Little\\Ingenmandslandets\\Udsvvelsernes109.Taa" ascii //weight: 1
        $x_1_2 = "Software\\Fligen\\Velrettet" ascii //weight: 1
        $x_1_3 = "Afterpeak\\Albronze\\Morrice.Pak" ascii //weight: 1
        $x_1_4 = "Ratingskemaet\\Ydervgselementet\\Menneskealdrenes.lnk" ascii //weight: 1
        $x_1_5 = "Tracheitis\\Damefrisrinderne\\Rkefjende.Arm244" ascii //weight: 1
        $x_1_6 = "Testkrslerne\\Subquality\\Integrationer\\Bedspreads.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPY_2147850873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPY!MTB"
        threat_id = "2147850873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\somniate\\salgssituations.Opa149" ascii //weight: 1
        $x_1_2 = "\\scaphism\\unoptimistically.ini" ascii //weight: 1
        $x_1_3 = "\\flavourlesses\\Baubling\\Sammenrullende.ini" ascii //weight: 1
        $x_1_4 = "\\Hotels\\Profetiernes\\glasskaarene\\skonrogs.Aus155" ascii //weight: 1
        $x_1_5 = "afnazificerede.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPXV_2147851030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPXV!MTB"
        threat_id = "2147851030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dyrehospitals\\slibemiddel.dll" wide //weight: 1
        $x_1_2 = "oxidisations.pro" wide //weight: 1
        $x_1_3 = "Fruchtschiefer207\\Fnokurtens.ini" wide //weight: 1
        $x_1_4 = "emark.Kin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SSD_2147851080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SSD!MTB"
        threat_id = "2147851080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "morgenfruernes.teg" ascii //weight: 1
        $x_1_2 = "hmningslse.cow" ascii //weight: 1
        $x_1_3 = "Skatteberegnings.Eff" ascii //weight: 1
        $x_1_4 = "bhdH_ea" ascii //weight: 1
        $x_1_5 = "qupBmqm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CA_2147851289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CA!MTB"
        threat_id = "2147851289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Teltpladser\\Myliobatid\\Bewearied\\Perspektivrig.tur" ascii //weight: 1
        $x_1_2 = "suppletory%\\Undertonernes\\plisseer\\Svinglens.Reg2" ascii //weight: 1
        $x_1_3 = "triphyline\\Boligtilsynenes.ini" ascii //weight: 1
        $x_1_4 = "Genkbsvrdiers\\lindberg\\Blikfanget\\Fedteras" ascii //weight: 1
        $x_1_5 = "Secularises\\Cytoplasmas\\Raspningers\\Seychelliskes.Sto" ascii //weight: 1
        $x_1_6 = "Bortgaar\\mortared\\Iridesce\\Supersets.Unl" ascii //weight: 1
        $x_1_7 = "Ingraining\\tegnebgernes.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CC_2147851610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CC!MTB"
        threat_id = "2147851610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eksportlaanet\\Haylofts\\iter\\bicyanide.dll" ascii //weight: 1
        $x_1_2 = "airshed\\breviarerne\\refrigeration\\philip.emb" ascii //weight: 1
        $x_1_3 = "nedrulledes\\etherealizations\\Godartede255\\whiskers.ini" ascii //weight: 1
        $x_1_4 = "kombinationsmulighed\\ejendomsselskabet\\gobble\\sadler.mon" ascii //weight: 1
        $x_1_5 = "computes\\redesigning\\uforsonligere.lnk" ascii //weight: 1
        $x_1_6 = "tandfyldningerne\\Wardrobes63\\ivanas.lnk" ascii //weight: 1
        $x_1_7 = "Tilbagefrsels\\ngent.tri" ascii //weight: 1
        $x_1_8 = "Software\\Aabningskampenes\\Doper\\Sporskifternes165\\Flannelflower" ascii //weight: 1
        $x_1_9 = "Eluviates233\\Puristic.lnk" ascii //weight: 1
        $x_1_10 = "Dyknders\\Philanthropised\\Bethlehemite\\Sororize.Ufl" ascii //weight: 1
        $x_1_11 = "Hardfistedness234\\Udviklingsegnene184.Mic" ascii //weight: 1
        $x_1_12 = "valdrapperne\\Machination.Blo" ascii //weight: 1
        $x_1_13 = "Kalendermenu38\\Jammerligst\\Jenkontakternes\\Asynchron.Win255" ascii //weight: 1
        $x_1_14 = "Dematerialized%\\Sibensbetndelser.Gua" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Guloader_SPXC_2147852665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPXC!MTB"
        threat_id = "2147852665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Delomraade.Aff" ascii //weight: 1
        $x_1_2 = "Disdiplomatize.ove" ascii //weight: 1
        $x_1_3 = "Pampas.sni" ascii //weight: 1
        $x_1_4 = "Software\\Melodying\\meandrous" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPED_2147889123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPED!MTB"
        threat_id = "2147889123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vsentlighedskriteriets\\sprren\\gogopigen" ascii //weight: 1
        $x_1_2 = "Unik\\smertendes\\parlormaid.fil" ascii //weight: 1
        $x_1_3 = "farmy\\stamherrers\\skobrster.dea" ascii //weight: 1
        $x_1_4 = "Elevated\\bevillingsmssigt" ascii //weight: 1
        $x_1_5 = "noncombining.bes" ascii //weight: 1
        $x_1_6 = "spermatozoic.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CD_2147892388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CD!MTB"
        threat_id = "2147892388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dybklede\\Uninstall\\tekstningen\\Milieuernes\\Biologiklasser\\scramb" ascii //weight: 1
        $x_1_2 = "teloblastic.skr" ascii //weight: 1
        $x_1_3 = "warmers\\Aeropause110.tin" ascii //weight: 1
        $x_1_4 = "frictionproof%\\Slavebundet62" ascii //weight: 1
        $x_1_5 = "Software\\Equilobate\\springwort\\betror\\boblekammers" ascii //weight: 1
        $x_1_6 = "cimnel\\plashy.dll" ascii //weight: 1
        $x_1_7 = "Hallmoot\\Amidone\\Sexbombes\\textarian" ascii //weight: 1
        $x_1_8 = "Unreverberant\\Unperjuring91\\Untrochaic\\Brattingsborg" ascii //weight: 1
        $x_1_9 = "Reduplikation\\Liggedage105\\Hikkets\\Variabelerklringer" ascii //weight: 1
        $x_1_10 = "Phonophore.rat" ascii //weight: 1
        $x_1_11 = "Gennembrudskrfternes\\femkants.lnk" ascii //weight: 1
        $x_1_12 = "djvlekulten\\kondensatorerne.vir" ascii //weight: 1
        $x_1_13 = "Budbringeren.aad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Guloader_SED_2147892394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SED!MTB"
        threat_id = "2147892394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Skibstilsynslovs62.kon" wide //weight: 1
        $x_1_2 = "baldrianolies.vit" wide //weight: 1
        $x_1_3 = "programmeringerne.ska" wide //weight: 1
        $x_1_4 = "spillecomputer.kos" wide //weight: 1
        $x_1_5 = "wienerbrdsstang.blo" wide //weight: 1
        $x_1_6 = "sigtelinjen.oat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CE_2147895815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CE!MTB"
        threat_id = "2147895815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Punaluan237.lyn" ascii //weight: 1
        $x_1_2 = "luftfartslovene.txt" ascii //weight: 1
        $x_1_3 = "subpotencies.wea" ascii //weight: 1
        $x_1_4 = "Menstruerendes254.mat" ascii //weight: 1
        $x_1_5 = "Software\\tuske" ascii //weight: 1
        $x_1_6 = "dyrekropper.hyp" ascii //weight: 1
        $x_1_7 = "Pinjers62.sam" ascii //weight: 1
        $x_1_8 = "kontorautomatiseringer\\andamanese.dll" ascii //weight: 1
        $x_1_9 = "Multiplikationers.udb" ascii //weight: 1
        $x_1_10 = "Software\\inddatafilen\\slutskema" ascii //weight: 1
        $x_1_11 = "tylvt\\Showeriness.ini" ascii //weight: 1
        $x_1_12 = "empirekjolers.txt" ascii //weight: 1
        $x_1_13 = "tapeinocephalic\\Nonimitative" ascii //weight: 1
        $x_1_14 = "uncolored%\\Chefkokkens191\\dannekvindens.off" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Guloader_CF_2147895816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CF!MTB"
        threat_id = "2147895816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "alabastfabrikker\\teleinfrastrukturen.ini" ascii //weight: 1
        $x_1_2 = "c:\\temp\\a.txt" ascii //weight: 1
        $x_1_3 = "Sandboxes59\\vismuts.ini" ascii //weight: 1
        $x_1_4 = "Software\\gangestykkernes" ascii //weight: 1
        $x_1_5 = "digitalurenes.tra" ascii //weight: 1
        $x_1_6 = "Transited106.Hor" ascii //weight: 1
        $x_1_7 = "Software\\amtsskatteinspektorat\\menneske" ascii //weight: 1
        $x_1_8 = "fillipinske\\Ubesmittede210.dll" ascii //weight: 1
        $x_1_9 = "herser\\behovsundersgelsernes.ini" ascii //weight: 1
        $x_1_10 = "Software\\udkldningen\\trickliest" ascii //weight: 1
        $x_1_11 = "unfibered%\\klaskenes\\tawkee.Baa" ascii //weight: 1
        $x_1_12 = "gennemarbejdelser.bss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Guloader_SPQE_2147896061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPQE!MTB"
        threat_id = "2147896061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sovehjerternes1+0)" ascii //weight: 1
        $x_1_2 = "montagnac@Uddelegeringer.big1(0&" ascii //weight: 1
        $x_1_3 = "Utyskestreg Ambulancechauffrer 1" ascii //weight: 1
        $x_1_4 = "sovehjerternes0" ascii //weight: 1
        $x_1_5 = "20221123014206Z0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPLD_2147897724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPLD!MTB"
        threat_id = "2147897724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kontobestemte.tur" wide //weight: 1
        $x_1_2 = "Amphibiology.txt" wide //weight: 1
        $x_1_3 = "Scanter.mis" wide //weight: 1
        $x_1_4 = "ciselerer.ark" wide //weight: 1
        $x_1_5 = "isoetales.hof" wide //weight: 1
        $x_1_6 = "Poblacht51.udt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SMTF_2147898446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SMTF!MTB"
        threat_id = "2147898446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 08 88 4d fe 0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fe 33 d1 8b 45 f4 03 45 f8 88 10 8b 45 e0 83 c0 01 99 b9 0d 00 00 00 f7 f9 89 55 e0 eb a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPDD_2147900586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPDD!MTB"
        threat_id = "2147900586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nppe.hos" wide //weight: 1
        $x_1_2 = "hornists.ini" wide //weight: 1
        $x_1_3 = "Kaukasieres64.sem" wide //weight: 1
        $x_1_4 = "andelskapitalers.tar" wide //weight: 1
        $x_1_5 = "skrivebordstesten" wide //weight: 1
        $x_1_6 = "gesithcundman.tra" wide //weight: 1
        $x_1_7 = "cinephotomicrography.rev" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CG_2147900597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CG!MTB"
        threat_id = "2147900597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 80 b3 59 85 b6 5f 8a b9 66 8f bc 6d 94 bf 73 99 c2 79}  //weight: 1, accuracy: High
        $x_1_2 = {55 82 b4 5b 87 b7 62 8b ba 68 90 bd 6d 94 c1 73 98 c4 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CH_2147901014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CH!MTB"
        threat_id = "2147901014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 f4 2d 7a 9e 35 aa 19 cf 2d fd f1 23 2e ec 16 b1 80 74}  //weight: 1, accuracy: High
        $x_1_2 = {2d 05 78 56 0d fc f1 d3 7f 15 d4 d3 2d fd fa 24 1c bc 7b 20 d7 d4 ab 93 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPYY_2147901086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPYY!MTB"
        threat_id = "2147901086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cretinous15\\Underdrejningens" wide //weight: 1
        $x_1_2 = "printproblemet\\doedt.ini" wide //weight: 1
        $x_1_3 = "lyskopi\\fallossymbolet.ini" wide //weight: 1
        $x_1_4 = "Plasmogamy.beg" wide //weight: 1
        $x_1_5 = "tidsstempler.vel" wide //weight: 1
        $x_1_6 = "Euryale.baj" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CK_2147902899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CK!MTB"
        threat_id = "2147902899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "differencing\\krybskytten\\supramaxillary" ascii //weight: 1
        $x_1_2 = "blgeskrets.bog" ascii //weight: 1
        $x_1_3 = "eneanpartshaver.der" ascii //weight: 1
        $x_1_4 = "hyldeblomsten.txt" ascii //weight: 1
        $x_1_5 = "Trophi\\formatlngdens.lnk" ascii //weight: 1
        $x_1_6 = "rockwoolen.bra " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Guloader_CL_2147903152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CL!MTB"
        threat_id = "2147903152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "retsstaten\\bondeangerens.lnk" ascii //weight: 1
        $x_1_2 = "housewarmer\\lsningsmodellens.fer" ascii //weight: 1
        $x_1_3 = "nongeological\\underdnningens.ini" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\ynkelige\\Uninstall\\energimarked\\leggy" ascii //weight: 1
        $x_1_5 = "orlogskaptajnerne\\Theriotrophical.ini" ascii //weight: 1
        $x_1_6 = "trachearian\\erythrine.Mou" ascii //weight: 1
        $x_1_7 = "Diesellokomotivets%\\luxemburg.Bef" ascii //weight: 1
        $x_1_8 = "Peuhl153\\Sindssvagestes.cir" ascii //weight: 1
        $x_1_9 = "nationalindkomsternes.txt" ascii //weight: 1
        $x_1_10 = "Software\\Tekstilarbejderen\\gauntlet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Guloader_CM_2147903153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CM!MTB"
        threat_id = "2147903153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\indbyggerantal\\kammy" ascii //weight: 1
        $x_1_2 = "braktuds\\strapning.ini" ascii //weight: 1
        $x_1_3 = "polemicises%\\intercrystallises\\holoproteide.pos" ascii //weight: 1
        $x_1_4 = "Hollywoodskuespiller\\korresponderedes.ini" ascii //weight: 1
        $x_1_5 = "bedreviden\\sandastra.sul" ascii //weight: 1
        $x_1_6 = "Software\\indskydninger\\apokryfen" ascii //weight: 1
        $x_1_7 = "Sladdertasker176.rom" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\bsseskuds\\Uninstall\\Paahaeftningen\\idrtsklub" ascii //weight: 1
        $x_1_9 = "Software\\raadvildes\\udfrselsforbuddenes" ascii //weight: 1
        $x_1_10 = "Longheads%\\teksttypernes.par" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Guloader_CN_2147903583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CN!MTB"
        threat_id = "2147903583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tromlerevolvers\\Specsartine65.ini" ascii //weight: 1
        $x_1_2 = "mochila\\borofluorin.ini" ascii //weight: 1
        $x_1_3 = "reklamefilmen\\Brnetilskuddets.smu" ascii //weight: 1
        $x_1_4 = "Software\\nglepersons\\undvigemanvrer" ascii //weight: 1
        $x_1_5 = "knarl%\\Antereformational.tri" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CCHU_2147904523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CCHU!MTB"
        threat_id = "2147904523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hotdoggen.ini" ascii //weight: 1
        $x_1_2 = "Kapsejler\\segles" ascii //weight: 1
        $x_1_3 = "replight.ini" ascii //weight: 1
        $x_1_4 = "Mundstykket.min" ascii //weight: 1
        $x_1_5 = "outferret.ugy" ascii //weight: 1
        $x_1_6 = "Grundstds\\battledresset" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AMMB_2147904782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AMMB!MTB"
        threat_id = "2147904782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "paramenia kuld masterwork" wide //weight: 1
        $x_1_2 = "faresoen" wide //weight: 1
        $x_1_3 = "tilmelde fondssystemerne" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_KAA_2147905522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.KAA!MTB"
        threat_id = "2147905522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 45 ec 06 47 48 b0 bd 82 83 bc ff e9 ea f4 fe d3 d4 e8 ff ba bc db fe}  //weight: 1, accuracy: High
        $x_1_2 = {48 46 e3 0e 4a 47 9e ed 94 93 c2 ff c4 c4 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SMKT_2147905697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SMKT!MTB"
        threat_id = "2147905697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Undermaalerens45\\sobriquets" ascii //weight: 1
        $x_1_2 = "\\touses\\manucode\\saburrate\\vibrationer.ini" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\frsteinstanser\\blomkaalssvampes\\physiognomically\\tove" ascii //weight: 1
        $x_1_4 = "Sensibiliseringernes" ascii //weight: 1
        $x_1_5 = "aarsungen" ascii //weight: 1
        $x_1_6 = "\\Oldsters\\chinniest\\uteroplacental.skn" ascii //weight: 1
        $x_1_7 = "Hustelefon.Cou" ascii //weight: 1
        $x_1_8 = "Green_Leaves_18.bmp" ascii //weight: 1
        $x_1_9 = "\\Palaeoanthropology" ascii //weight: 1
        $x_1_10 = "\\Backupmoduler" ascii //weight: 1
        $x_1_11 = "\\Nybruds\\dagcentrer.una" ascii //weight: 1
        $x_1_12 = "Iscremerne59" ascii //weight: 1
        $x_1_13 = "\\Iblandende\\Dragonernes.Mix" ascii //weight: 1
        $x_1_14 = "\\coaxial\\kartagisk.dll" ascii //weight: 1
        $x_1_15 = "Software\\cirriform\\loofah\\scopuliped\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_Guloader_SOP_2147905709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SOP!MTB"
        threat_id = "2147905709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adfrd tveboplante.exe" ascii //weight: 1
        $x_1_2 = "Software\\Strikkemaskines90\\ruskurset" ascii //weight: 1
        $x_1_3 = "Software\\materiale\\nondemonstrativeness" ascii //weight: 1
        $x_1_4 = ".\\sammenstyknings.cen" ascii //weight: 1
        $x_1_5 = "Software\\Marcherendes\\" ascii //weight: 1
        $x_1_6 = "%Bindingly25%\\serviceteknikeres" ascii //weight: 1
        $x_1_7 = "Software\\Skuldrendes\\Pessarets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CO_2147907077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CO!MTB"
        threat_id = "2147907077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sanitariiums\\Gelatinating\\Bullfrogs" ascii //weight: 1
        $x_1_2 = "lutetiums%\\vasculomotor.tap" ascii //weight: 1
        $x_1_3 = "gidseltagningers.nyt" ascii //weight: 1
        $x_1_4 = "chiasmatype.txt" ascii //weight: 1
        $x_1_5 = "Knockless165.lul" ascii //weight: 1
        $x_1_6 = "kraftfuldheders\\Fide231\\recited" ascii //weight: 1
        $x_1_7 = "Software\\stereotypiernes\\knoklende" ascii //weight: 1
        $x_1_8 = "opalesces\\Redheadedness.lnk" ascii //weight: 1
        $x_1_9 = "bombedes%\\sengekanterne\\brevudveksling.Adj93" ascii //weight: 1
        $x_1_10 = "protreptic\\Slagtekvgsmarkeder253.agr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Guloader_CP_2147907477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CP!MTB"
        threat_id = "2147907477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Butikstidens150\\heluldent\\retrtens" ascii //weight: 1
        $x_1_2 = "Software\\skirtingly\\kloakken" ascii //weight: 1
        $x_1_3 = "produktevalueringers\\farbares.dll" ascii //weight: 1
        $x_1_4 = "unhashed.txt" ascii //weight: 1
        $x_1_5 = "vandyked\\Udliggerbaade.bel" ascii //weight: 1
        $x_1_6 = "Subpreceptoral.tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CQ_2147914532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CQ!MTB"
        threat_id = "2147914532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vapourisable111\\orthos\\interregna" ascii //weight: 1
        $x_1_2 = "piezocrystallization.dll" ascii //weight: 1
        $x_1_3 = "tetrazolyl\\ballonskippernes.lnk" ascii //weight: 1
        $x_1_4 = "snipsnapsnorum\\ganch.ove" ascii //weight: 1
        $x_1_5 = "Firmamenters\\Enkelthedernes.ini" ascii //weight: 1
        $x_1_6 = "rundbordssamtalernes\\dwt.udt" ascii //weight: 1
        $x_1_7 = "Normanneres144.taj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CR_2147915754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CR!MTB"
        threat_id = "2147915754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Meatal\\Sammenstningsleds\\Retsforflgninger" ascii //weight: 1
        $x_1_2 = "Lbegangens%\\Frysepunktssnknings\\pletter.sor" ascii //weight: 1
        $x_1_3 = "armadaers\\lokalplanomraader.ini" ascii //weight: 1
        $x_1_4 = "rebuttoning\\Kmpesals.per" ascii //weight: 1
        $x_1_5 = "henrejsers\\biographer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CCJB_2147915817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CCJB!MTB"
        threat_id = "2147915817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "udskaaret.ini" ascii //weight: 1
        $x_1_2 = "grovsortbfr\\curvative.bor" ascii //weight: 1
        $x_1_3 = "cykelsmedens.Rdg" ascii //weight: 1
        $x_1_4 = "hvsningens\\haandhvelsesloves.ini" ascii //weight: 1
        $x_1_5 = "Folketingstidenden226.Sta" ascii //weight: 1
        $x_1_6 = "Fabeldyrs\\procaciously.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CS_2147916830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CS!MTB"
        threat_id = "2147916830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "syncryptic.sum" ascii //weight: 1
        $x_1_2 = "orthopsychiatric.txt" ascii //weight: 1
        $x_1_3 = "courbe\\mytologiernes.dll" ascii //weight: 1
        $x_1_4 = "Sonarens\\spathose.ini" ascii //weight: 1
        $x_1_5 = "primtallene.Bet" ascii //weight: 1
        $x_1_6 = "Afkogninger233.sys" ascii //weight: 1
        $x_1_7 = "Kasts.bac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_KAB_2147917505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.KAB!MTB"
        threat_id = "2147917505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "molluginaceae" ascii //weight: 1
        $x_1_2 = "lithas" ascii //weight: 1
        $x_1_3 = "nikkende" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_PAFA_2147918100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.PAFA!MTB"
        threat_id = "2147918100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jammerlig.kle" ascii //weight: 1
        $x_1_2 = "baisakh\\straalingsfarens" ascii //weight: 1
        $x_1_3 = "bronkiernes inspektrs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CT_2147919378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CT!MTB"
        threat_id = "2147919378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pietetshensynene.dll" ascii //weight: 1
        $x_1_2 = "Embarkment\\Lovbestemmelserne59" ascii //weight: 1
        $x_1_3 = "mesenna\\gunbarrel.ini" ascii //weight: 1
        $x_1_4 = "polymicrobial\\Pappen33.mur" ascii //weight: 1
        $x_1_5 = "hexene\\erhvervsvejledningerne.dll" ascii //weight: 1
        $x_1_6 = "Imperalistisk\\Stjplages.tar" ascii //weight: 1
        $x_1_7 = "saucen\\helhederne\\befalingernes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CU_2147921657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CU!MTB"
        threat_id = "2147921657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ovariocentesis183.inv" ascii //weight: 1
        $x_1_2 = "Tnkeboksenes\\kjerstens\\soapbark" ascii //weight: 1
        $x_1_3 = "Coexchangeable237.dll" ascii //weight: 1
        $x_1_4 = "impious\\scabrous\\bazookamen" ascii //weight: 1
        $x_1_5 = "cradlelike.bry" ascii //weight: 1
        $x_1_6 = "Mescal246\\Uninstall\\projektopgavers\\iodhydric" ascii //weight: 1
        $x_1_7 = "nonplussing.blo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CV_2147921658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CV!MTB"
        threat_id = "2147921658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Slkningens147\\chaogenous.con" wide //weight: 1
        $x_1_2 = "velvillighed\\koncentrere.Flo178" wide //weight: 1
        $x_1_3 = "phytolithological\\ekskluderes.sad" wide //weight: 1
        $x_1_4 = "Skotvingen\\sidekammerater.Cin" wide //weight: 1
        $x_1_5 = "elffriend\\chemosmoic.ini" wide //weight: 1
        $x_1_6 = "elektronikteknikernes.dll" wide //weight: 1
        $x_1_7 = "nocktat\\Kartouchens.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_KAD_2147921795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.KAD!MTB"
        threat_id = "2147921795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "militaristerne.smo" ascii //weight: 1
        $x_1_2 = "momentvis.fin" ascii //weight: 1
        $x_1_3 = "Antiderivative" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SX_2147922997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SX!MTB"
        threat_id = "2147922997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bladkrigen.exe" ascii //weight: 1
        $x_1_2 = "Fradrage\\rabarbergrd\\jengene" ascii //weight: 1
        $x_1_3 = "mugged\\augmenters" ascii //weight: 1
        $x_1_4 = "%urethrogenital%\\medlem\\haandtagets.vel" ascii //weight: 1
        $x_1_5 = "affladningens\\automekanikeres\\foragteliges" ascii //weight: 1
        $x_1_6 = "busybodyness.hje" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SLA_2147923394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SLA!MTB"
        threat_id = "2147923394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Understatementens" ascii //weight: 1
        $x_1_2 = "radiolitic thionines" ascii //weight: 1
        $x_1_3 = "fjernkontrollers.hid" ascii //weight: 1
        $x_1_4 = "irresolubleness.hje" ascii //weight: 1
        $x_1_5 = "paasknnende applegrower" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPBI_2147923433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPBI!MTB"
        threat_id = "2147923433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Interviewteknikkerne.lan" ascii //weight: 2
        $x_1_2 = "stahlianism.reg" ascii //weight: 1
        $x_1_3 = "Bevarelse.lag" ascii //weight: 1
        $x_1_4 = "strophanthus.txt" ascii //weight: 1
        $x_1_5 = "frafaldene.pos" ascii //weight: 1
        $x_1_6 = "bremia.sur" ascii //weight: 1
        $x_1_7 = "Tiane.bal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SLB_2147924086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SLB!MTB"
        threat_id = "2147924086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Isbrydende.afr" ascii //weight: 1
        $x_1_2 = "Crystalizer.Syn" ascii //weight: 1
        $x_1_3 = "metabasis.ste" ascii //weight: 1
        $x_1_4 = "plasmolyzable.dem" ascii //weight: 1
        $x_1_5 = "vindspiller.cys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SLB_2147924086_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SLB!MTB"
        threat_id = "2147924086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tilslutningstoges vigtende entusiast" ascii //weight: 1
        $x_1_2 = "tildngede entomotomist trinskifterne" ascii //weight: 1
        $x_1_3 = "multifiler shendful.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SLC_2147924280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SLC!MTB"
        threat_id = "2147924280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "discourteously.gam" ascii //weight: 1
        $x_1_2 = "psychograph.rut" ascii //weight: 1
        $x_1_3 = "strudsfjerenes.uns" ascii //weight: 1
        $x_1_4 = "elia geomorfologi" ascii //weight: 1
        $x_1_5 = "illustrator obstinateness nonfealties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CCJC_2147924388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CCJC!MTB"
        threat_id = "2147924388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "europakontoret.Gal" ascii //weight: 1
        $x_1_2 = "Slubbering.voc" ascii //weight: 1
        $x_1_3 = "Emneomraader.beb" ascii //weight: 1
        $x_1_4 = "Generation.txt" ascii //weight: 1
        $x_1_5 = "cuttlefish.kic" ascii //weight: 1
        $x_5_6 = "skosvrten.dll" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CW_2147924703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CW!MTB"
        threat_id = "2147924703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rewoke40\\encephaloid.lnk" ascii //weight: 1
        $x_1_2 = "kevlar\\tenorsaxes.liv" ascii //weight: 1
        $x_1_3 = "knackaway\\klatgld\\Rgdykker227" ascii //weight: 1
        $x_1_4 = "Morbrdres\\Lempelsernes\\ynksomste" ascii //weight: 1
        $x_1_5 = "seksagesimas.fru" ascii //weight: 1
        $x_1_6 = "skrivelinien\\doeglic.pro" ascii //weight: 1
        $x_1_7 = "oversampled\\Opium.Gri" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_GB_2147924834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.GB!MTB"
        threat_id = "2147924834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetPrivateProfileStringW" ascii //weight: 1
        $x_1_2 = "WritePrivateProfileStringW" ascii //weight: 1
        $x_1_3 = "SetDefaultDllDirectories" ascii //weight: 1
        $x_2_4 = "SeShutdownPrivilege" wide //weight: 2
        $x_1_5 = "\\Temp" wide //weight: 1
        $x_4_6 = "andebryst reneglect.exe" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Guloader_GD_2147924838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.GD!MTB"
        threat_id = "2147924838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetTempFileNameW" ascii //weight: 1
        $x_1_2 = "ShellExecuteExW" ascii //weight: 1
        $x_1_3 = "SHGetSpecialFolderLocation" ascii //weight: 1
        $x_1_4 = "SeShutdownPrivilege" wide //weight: 1
        $x_1_5 = "\\Temp" wide //weight: 1
        $x_1_6 = "Error writing temporary file. Make sure your temp folder is valid." wide //weight: 1
        $x_5_7 = "udvalgsformnds produktansvar platitudinise" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Guloader_GTZ_2147925997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.GTZ!MTB"
        threat_id = "2147925997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bruised\\calypsoerne\\drikkelaget" ascii //weight: 1
        $x_1_2 = "patriotismen\\Aire.ini" ascii //weight: 1
        $x_1_3 = "jenkrogs\\statsskatterne.ini" ascii //weight: 1
        $x_1_4 = "trapper\\gennemtrawl.ini" ascii //weight: 1
        $x_1_5 = "brnefdselsdagen" ascii //weight: 1
        $x_1_6 = "erfaringer\\kalvekrsene.sab" ascii //weight: 1
        $x_1_7 = "Tillidshvervs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_GZZ_2147926174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.GZZ!MTB"
        threat_id = "2147926174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Upaavirkeliges5" ascii //weight: 2
        $x_2_2 = "appeasableness.txt" ascii //weight: 2
        $x_2_3 = "Basilikumernes.sys" ascii //weight: 2
        $x_2_4 = "glamouriser\\vite.gyn" ascii //weight: 2
        $x_2_5 = "zaffree\\taaens" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CY_2147926240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CY!MTB"
        threat_id = "2147926240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "underbindingerne.kon" ascii //weight: 2
        $x_2_2 = "Reventure175.rau" ascii //weight: 2
        $x_1_3 = "propangas.lem" ascii //weight: 1
        $x_1_4 = "synligeres.txt" ascii //weight: 1
        $x_1_5 = "farces.abs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_GZN_2147926367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.GZN!MTB"
        threat_id = "2147926367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "indklasseringer\\Pjerrot.dll" ascii //weight: 1
        $x_1_2 = "Farisismen24.opt" ascii //weight: 1
        $x_1_3 = "semiriddle.flg" ascii //weight: 1
        $x_1_4 = "tekstilarbejderens.txt" ascii //weight: 1
        $x_1_5 = "tegnesystemer\\selvmordsbaade.bar" ascii //weight: 1
        $x_1_6 = "traveskoen.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_CZ_2147926738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.CZ!MTB"
        threat_id = "2147926738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "narrowness.ini" ascii //weight: 2
        $x_2_2 = "befolkningsgrupper\\moras.zon" ascii //weight: 2
        $x_1_3 = "Hyldebrret2.faj" ascii //weight: 1
        $x_1_4 = "pelvetia.txt" ascii //weight: 1
        $x_1_5 = "sakkende.dro" ascii //weight: 1
        $x_1_6 = "Aftrkkes\\ramshorn\\lachrymaeform" ascii //weight: 1
        $x_1_7 = "Glyphograph\\Malvaceae56\\altruisten" ascii //weight: 1
        $x_1_8 = "energiudfoldelsers.Uku" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASB_2147926960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASB!MTB"
        threat_id = "2147926960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "guidsire\\Anlgsgartneriet.lnk" ascii //weight: 2
        $x_2_2 = "Xanthopsin8\\diamb.lit" ascii //weight: 2
        $x_1_3 = "Jungmandens15\\fiskefartjer" ascii //weight: 1
        $x_1_4 = "phytosociologically.txt" ascii //weight: 1
        $x_1_5 = "Fredsvalget214\\nationalindkomsten" ascii //weight: 1
        $x_1_6 = "hampton.ant" ascii //weight: 1
        $x_1_7 = "konomiseret\\Uninstall\\gerontologic" ascii //weight: 1
        $x_1_8 = "bjergkrystallen.sam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPBD_2147927545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPBD!MTB"
        threat_id = "2147927545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "nitrostarch\\grankoglerne.Vid199" wide //weight: 3
        $x_2_2 = "Anstdelighedens214\\*.opk" wide //weight: 2
        $x_1_3 = "jactitated.rep" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASC_2147928050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASC!MTB"
        threat_id = "2147928050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "morbidises\\Enrive\\Twaddlier\\milieugiftes.ini" ascii //weight: 2
        $x_1_2 = "Tonsillar\\Marginiform\\Muskmelon" ascii //weight: 1
        $x_1_3 = "Tympaniform%\\Kalfaktor\\Samfundsbevidst\\Filkaldets\\Brevbrerens.Bin" ascii //weight: 1
        $x_1_4 = "Dysidrosis\\Ilmarchens\\Graedefaerdig\\Bummalo" ascii //weight: 1
        $x_1_5 = "Duplikatets\\imperativer\\Samfundsnyttehensyns\\Neurolymph.ini" ascii //weight: 1
        $x_1_6 = "Linjevogters\\telefonboksene.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASE_2147928605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASE!MTB"
        threat_id = "2147928605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Phylogenetically.del" ascii //weight: 2
        $x_1_2 = "tommelskruerne.afs" ascii //weight: 1
        $x_1_3 = "inddatafunktionens.Tra" ascii //weight: 1
        $x_1_4 = "stilhederne\\tamtammens.ini" ascii //weight: 1
        $x_1_5 = "Kostbare.tes" ascii //weight: 1
        $x_1_6 = "Overhaling64\\Fes\\squanderer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_GTM_2147928989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.GTM!MTB"
        threat_id = "2147928989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\mafia\\sht.Rud" ascii //weight: 1
        $x_1_2 = "gehejmeraadernes kendetegnes fooyoung" ascii //weight: 1
        $x_1_3 = "tempestuously" ascii //weight: 1
        $x_1_4 = "bedsick dichromatopsia" ascii //weight: 1
        $x_1_5 = "Nrhedsbutikkens" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BSA_2147929326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BSA!MTB"
        threat_id = "2147929326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "lagere.exe" ascii //weight: 15
        $x_5_2 = "paridigitate dentninger" ascii //weight: 5
        $x_5_3 = "uncirostrate postglenoidal" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BSA_2147929326_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BSA!MTB"
        threat_id = "2147929326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 77 61 72 65 5c 67 72 61 76 69 64 69 74 65 74 5c 74 72 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 74 77 61 72 65 5c 54 69 6c 73 61 67 6e 73 74 69 6c 6c 67 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 76 6f 69 64 65 72 2e 69 6e 69 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 76 65 72 62 75 6d 2e 66 61 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 6e 69 6e 73 74 61 6c 6c 5c 73 6c 61 74 74 65 72 6e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BSA_2147929326_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BSA!MTB"
        threat_id = "2147929326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Hjmessens\\porn" ascii //weight: 1
        $x_1_2 = "faststtelsens\\lithographer" ascii //weight: 1
        $x_1_3 = "trangest\\ichneumoned.Arb186" ascii //weight: 1
        $x_1_4 = "enhydritic\\bawly.pau" ascii //weight: 1
        $x_15_5 = "\\Drops\\Stramnings\\Rigsarkiver" ascii //weight: 15
        $x_11_6 = "Anagrammatised.Gob" ascii //weight: 11
        $x_1_7 = "trimon.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BSA_2147929326_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BSA!MTB"
        threat_id = "2147929326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Brandmanden89\\banner\\sivet\\prechallenging.ini" ascii //weight: 1
        $x_1_2 = "Software\\andenprmiers\\bladformig" ascii //weight: 1
        $x_15_3 = "disseminative\\Veneracean.ini" ascii //weight: 15
        $x_1_4 = "postvenereal\\eskorteringerne.bla" ascii //weight: 1
        $x_1_5 = "Adversion.txt" ascii //weight: 1
        $x_11_6 = "Afringningens39\\Gammelost7" ascii //weight: 11
        $x_1_7 = "\\caddie\\infrangible.eth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASF_2147930853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASF!MTB"
        threat_id = "2147930853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ramtils\\Formaldehyds\\tyngdepunkterne" ascii //weight: 2
        $x_2_2 = "brudsikreste.txt" ascii //weight: 2
        $x_1_3 = "arrogantly.wea" ascii //weight: 1
        $x_1_4 = "vagabondage.fis" ascii //weight: 1
        $x_1_5 = "kreditdage\\yielden" ascii //weight: 1
        $x_1_6 = "Heteroscian234%\\sammentraadte\\kerseymere" ascii //weight: 1
        $x_1_7 = "badmitons\\garantisedlerne.bek" ascii //weight: 1
        $x_1_8 = "vanskbnerne%\\sprogklfts\\Photocomposes.con" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RVDU_2147931778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RVDU!MTB"
        threat_id = "2147931778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\spotmarkedets\\lipoidic.ini" ascii //weight: 1
        $x_1_2 = "\\Doed\\basiliskens" ascii //weight: 1
        $x_1_3 = "krameriaceous hannas geosynclinal" ascii //weight: 1
        $x_1_4 = "videoplader frperspektivers" ascii //weight: 1
        $x_1_5 = "vesteuroper.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASG_2147931798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASG!MTB"
        threat_id = "2147931798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Outspans\\Herb\\Molinia38\\Dummyspillere.Cam" ascii //weight: 2
        $x_1_2 = "Smukkeserende%\\fnuggenes.Kol" ascii //weight: 1
        $x_1_3 = "Whatsomever\\Jyndevads\\Indboforsikringerne228\\Befalet.Fre" ascii //weight: 1
        $x_1_4 = "Hoejrelineaer.Svi" ascii //weight: 1
        $x_1_5 = "Software\\Sunket191\\Periaortitis" ascii //weight: 1
        $x_1_6 = "Tematisere\\Hosekraemmeren208" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RVDX_2147931936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RVDX!MTB"
        threat_id = "2147931936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\deambulatories\\irrational\\amarillo" ascii //weight: 1
        $x_1_2 = "Perfuses\\fraflytningen" ascii //weight: 1
        $x_1_3 = "%kogerskerne%\\preacute\\patenterings" ascii //weight: 1
        $x_1_4 = "ajatsa drowns immunogenicity" ascii //weight: 1
        $x_1_5 = "foul homburg" ascii //weight: 1
        $x_1_6 = "ngo forlener.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RSA_2147932054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RSA!MTB"
        threat_id = "2147932054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regnskovs\\underprogrammers" ascii //weight: 1
        $x_1_2 = "\\lsesvage\\balestra.bis" ascii //weight: 1
        $x_1_3 = "sommerferier jackrolls" ascii //weight: 1
        $x_1_4 = "gravestones domorganister orsino" ascii //weight: 1
        $x_1_5 = "overpresumptiveness fiberizing etapevist" ascii //weight: 1
        $x_1_6 = "sensationslyst melassigenic cuminole" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_RSC_2147932534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.RSC!MTB"
        threat_id = "2147932534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Klippespaltens67\\metodikeren.tax" ascii //weight: 1
        $x_1_2 = "Diegivningers\\decentraliseringspolitikkers" ascii //weight: 1
        $x_1_3 = "%santiago%\\afsyngningerne" ascii //weight: 1
        $x_1_4 = "%Blomsterbutikkernes%\\overbebyggelses.ove" ascii //weight: 1
        $x_1_5 = "99\\popover.ini" ascii //weight: 1
        $x_1_6 = "\\Langfibrede.Unt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SBM_2147932787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SBM!MTB"
        threat_id = "2147932787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bldgringers.cry" ascii //weight: 2
        $x_2_2 = "Chorusses247.scu" ascii //weight: 2
        $x_2_3 = "intercalated.sas" ascii //weight: 2
        $x_2_4 = "sardiskes.res" ascii //weight: 2
        $x_1_5 = "Overtegnedes16\\nedbrydelige.par" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASI_2147933232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASI!MTB"
        threat_id = "2147933232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "apotekerbevillings.txt" ascii //weight: 1
        $x_1_2 = "trningsdragternes\\misdannes\\Tekstilfarvers" ascii //weight: 1
        $x_1_3 = "tyverisikrendes.dll" ascii //weight: 1
        $x_1_4 = "Unrhymed.adi" ascii //weight: 1
        $x_1_5 = "christianshavnerne.deh" ascii //weight: 1
        $x_1_6 = "stoppegarns.bra" ascii //weight: 1
        $x_1_7 = "normalfordelte.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SVM_2147933263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SVM!MTB"
        threat_id = "2147933263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "quadriciliate.txt" ascii //weight: 2
        $x_2_2 = "budgereegah.jpg" ascii //weight: 2
        $x_2_3 = "avisskriverier.jpg" ascii //weight: 2
        $x_2_4 = "Tekstmasses227.ini" ascii //weight: 2
        $x_2_5 = "Retroposed.jpg" ascii //weight: 2
        $x_2_6 = "Delbetalingers.txt" ascii //weight: 2
        $x_2_7 = "contractibleness\\breblgernes" ascii //weight: 2
        $x_1_8 = "skruetrkkeres.mus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AQ_2147933693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AQ!MTB"
        threat_id = "2147933693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "interruptory\\driftschefs.zip" ascii //weight: 1
        $x_1_2 = "brugerdisciplinen\\aktuaren.txt" ascii //weight: 1
        $x_1_3 = "faconstaalet\\guahiban" ascii //weight: 1
        $x_1_4 = "immatures\\dividerer\\paleostylic" ascii //weight: 1
        $x_1_5 = "monoureide.bin" ascii //weight: 1
        $x_1_6 = "subtilised\\esquiline.ini" ascii //weight: 1
        $x_1_7 = "lycoperdon.cyl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASJ_2147934135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASJ!MTB"
        threat_id = "2147934135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thermels\\dekaterendes.ini" ascii //weight: 1
        $x_1_2 = "tikronesedler\\phytogeographical" ascii //weight: 1
        $x_1_3 = "Nonsubsistent.txt" ascii //weight: 1
        $x_1_4 = "elektronikfirmaer\\Vestibulers.ger" ascii //weight: 1
        $x_1_5 = "aphrodesiac\\Uninstall\\carte\\financiered" ascii //weight: 1
        $x_1_6 = "featheriest\\Shadoof76.Sky143" ascii //weight: 1
        $x_1_7 = "querimoniously\\Nematognathous.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SVVM_2147934639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SVVM!MTB"
        threat_id = "2147934639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "weatherstripped.jpg" wide //weight: 2
        $x_2_2 = "trimpregneringers.jpg" wide //weight: 2
        $x_2_3 = "skovlbernes.ini" wide //weight: 2
        $x_2_4 = "mayhemming.jpg" wide //weight: 2
        $x_2_5 = "brodernationerne.ini" wide //weight: 2
        $x_1_6 = "autoritetstroens.rig" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_BA_2147935986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.BA!MTB"
        threat_id = "2147935986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cheilostomata.ini" ascii //weight: 2
        $x_2_2 = "christins.alk" ascii //weight: 2
        $x_2_3 = "Jende\\raakost" ascii //weight: 2
        $x_2_4 = "rhesuspositiv" ascii //weight: 2
        $x_2_5 = "Teksbehandlingsfaciliteter" ascii //weight: 2
        $x_2_6 = "Recants\\kirsebrsten" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AB_2147935990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AB!MTB"
        threat_id = "2147935990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "derimellem.ini" ascii //weight: 2
        $x_2_2 = "Snorelofts.sam" ascii //weight: 2
        $x_2_3 = "stridsmndene.jpg" ascii //weight: 2
        $x_2_4 = "overfyldte\\slavepen" ascii //weight: 2
        $x_2_5 = "udvirkninger\\Philosophership" ascii //weight: 2
        $x_2_6 = "polysomatic.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AE_2147936272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AE!MTB"
        threat_id = "2147936272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "seguendo.ini" ascii //weight: 2
        $x_2_2 = "polemicising.ini" ascii //weight: 2
        $x_2_3 = "Crablike.for" ascii //weight: 2
        $x_2_4 = "sabbatsaftens.jpg" ascii //weight: 2
        $x_2_5 = "Teaboxes\\heptaploidy" ascii //weight: 2
        $x_2_6 = "meganthropus\\arietta" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASK_2147940010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASK!MTB"
        threat_id = "2147940010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Eyelessness\\carousals\\kammerjunkernes" ascii //weight: 1
        $x_1_2 = "upbuoy\\Seigniorage.htm" ascii //weight: 1
        $x_1_3 = "bloktilbagekoblingschip\\mathematicize" ascii //weight: 1
        $x_1_4 = "Badevrelsers.imp" ascii //weight: 1
        $x_1_5 = "skndselsgerningernes.txt" ascii //weight: 1
        $x_1_6 = "dulcification.ini" ascii //weight: 1
        $x_1_7 = "videobaandoptageren.sen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASL_2147940813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASL!MTB"
        threat_id = "2147940813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loesrivelsen.exe" ascii //weight: 1
        $x_1_2 = "Hyldebuskene\\produktionsregels.gif" ascii //weight: 1
        $x_1_3 = "Regimentsstabe170\\viannas.lnk" ascii //weight: 1
        $x_1_4 = "Alarmijr184\\gormandizing.ini" ascii //weight: 1
        $x_1_5 = "vituper\\vectorially.jpg" ascii //weight: 1
        $x_1_6 = "mystifikationernes.sou" ascii //weight: 1
        $x_1_7 = "Zereba12.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_ASN_2147941170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.ASN!MTB"
        threat_id = "2147941170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "moneychanger\\submicrogram\\Tailorisation117" ascii //weight: 1
        $x_1_2 = "Reduktioner211\\Uninstall\\vocalist\\Regionsplanretningslinje" ascii //weight: 1
        $x_1_3 = "alkali\\Uninstall\\Iconically95" ascii //weight: 1
        $x_1_4 = "Imperialises%\\squibb.txt" ascii //weight: 1
        $x_1_5 = "Vrdiskabende32.jpg" ascii //weight: 1
        $x_1_6 = "dokumentfalskner\\heltalsvaerdier.exe" ascii //weight: 1
        $x_1_7 = "skiegh\\empathised.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AO_2147941811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AO!MTB"
        threat_id = "2147941811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kommunikationskommando.ret" ascii //weight: 1
        $x_1_2 = "Akkvisitivt.lnk" ascii //weight: 1
        $x_1_3 = "Fibertilskud.Hom" ascii //weight: 1
        $x_1_4 = "PROGRAMFILES%\\Infanterienheder2.fan" ascii //weight: 1
        $x_1_5 = "Bindemiddelets120.dll" ascii //weight: 1
        $x_1_6 = "Sniglbe225.HAN" ascii //weight: 1
        $x_1_7 = "Inkaminationens.str" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SLEF_2147943697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SLEF!MTB"
        threat_id = "2147943697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hurtlingly ergometercyklen.exe" wide //weight: 2
        $x_2_2 = "polyphasal snotnset" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_AS_2147943981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.AS!MTB"
        threat_id = "2147943981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "overliberalized\\gaestfri\\antigonorrheal" ascii //weight: 1
        $x_1_2 = "plastre\\Interessesammenfaldets.ini" ascii //weight: 1
        $x_1_3 = "vsentlighedskriterium.txt" ascii //weight: 1
        $x_1_4 = "Antikverets173\\Demiurgic" ascii //weight: 1
        $x_1_5 = "Theophilosophic\\chirruping.ini" ascii //weight: 1
        $x_1_6 = "Buffing\\unexplained.htm" ascii //weight: 1
        $x_1_7 = "unlubricative.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPS_2147944782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPS!MTB"
        threat_id = "2147944782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dekuprerne" wide //weight: 2
        $x_2_2 = "Plsefabrikanter108" wide //weight: 2
        $x_1_3 = "wauregan\\agronoms" wide //weight: 1
        $x_1_4 = "Hejrers185\\Bortfiltrering" wide //weight: 1
        $x_1_5 = "monophonic\\Uninstall\\Betonien\\retshandler" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SLUP_2147944793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SLUP!MTB"
        threat_id = "2147944793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\sprngemners.ini" wide //weight: 2
        $x_2_2 = "\\udgavernes.htm" wide //weight: 2
        $x_2_3 = "autochthonal.run" wide //weight: 2
        $x_2_4 = "Unbeatably\\rustet\\bredninger" wide //weight: 2
        $x_2_5 = "trforarbejdningsvirksomheds\\ekoi\\taagedes" wide //weight: 2
        $x_2_6 = "antibiotika.jpg" wide //weight: 2
        $x_2_7 = "stikpillerne.sli" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SLTI_2147944920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SLTI!MTB"
        threat_id = "2147944920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lektoraternes.txt" wide //weight: 2
        $x_2_2 = "adgangskursus.txt" wide //weight: 2
        $x_2_3 = "forandringsuvillig.bur" wide //weight: 2
        $x_2_4 = "schizoneura.jpg" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SLHE_2147945502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SLHE!MTB"
        threat_id = "2147945502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Typicon\\Kuomintang" ascii //weight: 2
        $x_2_2 = "Spildevandscirkulres25.gen" ascii //weight: 2
        $x_2_3 = "trafikelever.ini" ascii //weight: 2
        $x_2_4 = "\\subsystems\\reconciliability.htm" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SPF_2147946056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SPF!MTB"
        threat_id = "2147946056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Unsalubriously.jpg" ascii //weight: 2
        $x_2_2 = "knhje\\hypohyal" wide //weight: 2
        $x_1_3 = "Torumslejligheders\\pontal" ascii //weight: 1
        $x_1_4 = "betatrons.tid" ascii //weight: 1
        $x_1_5 = "coemptive.bri" ascii //weight: 1
        $x_1_6 = "objektiviseringers.txt" ascii //weight: 1
        $x_1_7 = "Scoreboards\\Forskydningers" ascii //weight: 1
        $x_1_8 = "soothsaw.afs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guloader_SLJH_2147946247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guloader.SLJH!MTB"
        threat_id = "2147946247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\sugarhouses\\rhomboides.lnk" wide //weight: 2
        $x_2_2 = "Standardprodukter\\telegramme" wide //weight: 2
        $x_2_3 = "\\Grammofonpladen7.htm\"" wide //weight: 2
        $x_2_4 = "periculous\\Transletter" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


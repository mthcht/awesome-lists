rule Trojan_Win64_Dridex_G_2147741711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.G!MTB"
        threat_id = "2147741711"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 48 83 ec 70 48 8d 6c 24 70 b8 dd 97 00 00 41 89 c1 b8 21 79 00 00 48 c7 45 f8 58 52 00 00 c7 45 f4 5e}  //weight: 1, accuracy: High
        $x_1_2 = {eb 88 a7 e4 12 3c b8 89 bb ce 8a 19 90 8a cf aa bc 8a d8 7e da 0a cb b1 cf e7 9b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GH_2147742133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GH!MTB"
        threat_id = "2147742133"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 83 ec 40 8b 44 24 3c 89 ca 09 c2 89 54 24 3c 48 c7 44 24 28 3a 51 d7 3d 4c 8b}  //weight: 10, accuracy: High
        $x_1_2 = {a0 37 b7 8d b9 8f}  //weight: 1, accuracy: High
        $x_1_3 = {9d 51 71 af a7}  //weight: 1, accuracy: High
        $x_1_4 = {e5 44 15 de 71 f2 89 ?? ?? e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GH_2147742133_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GH!MTB"
        threat_id = "2147742133"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 d8 41 f6 e2 88 84 24 0d 01 00 00 89 4c 24 ?? 4c 89 c1 44 8b 44 24 ?? e8 ?? ?? ?? ?? 48 8b 8c 24 d0 00 00 00 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {4c 89 f2 44 8b 5c 24 ?? 44 89 44 24 ?? 45 89 d8 8b 6c 24 ?? 44 89 4c 24 ?? 41 89 e9 48 89 7c 24 ?? ff d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GJ_2147742901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GJ!MTB"
        threat_id = "2147742901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 c7 84 24 b8 00 00 00 e3 79 6c 78 49 89 c0 4d 01 c0 4c 89 84 24 d8 00 00 00 49 89 c0 49 81 c8 5b b8 6a 07 4c 89 84 24 d8 00 00 00 83 fa 06}  //weight: 1, accuracy: High
        $x_1_2 = {3f 89 ea 39 b3 48 bf df 19 51 e6 f4 a6 34 75 a6 48 b3 05 bc 4b 25 9c ef e7 8f 97 e1 4a 37 08 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GG_2147745801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GG!MTB"
        threat_id = "2147745801"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nativeHslutInternetCanaryands" ascii //weight: 1
        $x_1_2 = "plug-ins3score.67wCcartman" ascii //weight: 1
        $x_1_3 = "Applicationusesflorida" ascii //weight: 1
        $x_1_4 = "Concurrently,inkJtranslationFPother" ascii //weight: 1
        $x_1_5 = "andsecurityvCourt.n" ascii //weight: 1
        $x_1_6 = "cbrowserfMozillaxdesktoponr" ascii //weight: 1
        $x_1_7 = "Chrome.162browsers.2008" ascii //weight: 1
        $x_1_8 = "EGooglelOffqQMl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win64_Dridex_GA_2147746110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GA!MTB"
        threat_id = "2147746110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 8a 1c 11 8b 84 24 ?? ?? ?? ?? 33 84 24 ?? ?? ?? ?? 43 8a 34 10 40 28 de 89 84 24 ?? ?? ?? ?? 4c 8b 84 24 ?? ?? ?? ?? 4c 8b 8c 24 ?? ?? ?? ?? 4c 29 c2 4c 29 c9 42 88 b4 14 ?? ?? ?? ?? 49 01 ca 48 8b 4c 24 ?? 48 89 8c 24 ?? ?? ?? ?? 4c 89 94 24 ?? ?? ?? ?? 48 89 8c 24 ?? ?? ?? ?? 49 39 d2 0f 84 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GA_2147746110_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GA!MTB"
        threat_id = "2147746110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "onupkreasoningChrome2RLZcInternet2008.28" ascii //weight: 10
        $x_10_2 = {42 8a 1c 0a 8b 44 24 ?? 83 f0 ff 48 8b 94 24 ?? ?? ?? ?? 44 28 d3 48 29 d1 89 84 24 ?? ?? ?? ?? 42 88 9c 0c ?? ?? ?? ?? 66 8b b4 24 ?? ?? ?? ?? 66 83 f6 ff 66 89 b4 24 ?? ?? ?? ?? 4d 01 d9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GA_2147746110_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GA!MTB"
        threat_id = "2147746110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 29 c8 48 89 44 24 ?? 49 81 f0 ?? ?? ?? ?? 44 8a 4c 24 01 41 80 c1 ?? 44 88 4c 24 ?? 44 8a 4c 24 ?? 48 8b 44 24 ?? 44 88 0c 10 44 8a 4c 24 ?? 41 80 e1 ?? 44 88 4c 24 ?? 4c 03 44 24 ?? c6 44 24 ?? 58 48 8b 4c 24 ?? 4c 89 44 24 ?? 44 8a 4c 24 ?? 41 80 e9 ?? 44 88 4c 24 ?? 49 39 c8 0f 84 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
        $x_1_2 = "FGT7t.pdb" ascii //weight: 1
        $x_1_3 = "raisingn587" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GA_2147746110_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GA!MTB"
        threat_id = "2147746110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BuildthesjUhackersinstance" ascii //weight: 1
        $x_1_2 = "versionStore.170hasT5ofZstableS" ascii //weight: 1
        $x_1_3 = "typedlifepsearchMayyaltogether.112" ascii //weight: 1
        $x_1_4 = "installingirexupdates.92hidden80vinwas6" ascii //weight: 1
        $x_1_5 = "anyInideasandSatypedpX" ascii //weight: 1
        $x_1_6 = "wasUthatGovernment" ascii //weight: 1
        $x_1_7 = "GoogleenginefasterturnscottSP" ascii //weight: 1
        $x_1_8 = "lBelfast,filedV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win64_Dridex_GZ_2147747987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GZ!MTB"
        threat_id = "2147747987"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 ca 8b 4c 24 ?? 83 f1 ff 4c 8b 84 24 [0-4] 89 8c 24 [0-4] 4c 8b 4c 24 ?? 4c 29 c2 4c 8b 44 24 ?? 49 81 f0 [0-4] 4c 89 44 24 ?? 4d 89 c8 49 21 d0}  //weight: 10, accuracy: Low
        $x_10_2 = {4c 8b 44 24 ?? 47 88 1c 08 66 8b 74 24 ?? 66 89 74 24 ?? 48 8b 7c 24 ?? 49 01 d1 66 69 74 24 ?? ?? ?? 66 89 74 24 ?? 4c 89 4c 24 ?? 49 39 f9 0f 84 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
        $x_1_3 = "FGT7t.pdb" ascii //weight: 1
        $x_1_4 = "raisingn587" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GB_2147748139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GB!MTB"
        threat_id = "2147748139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "halfbullshitTxC" ascii //weight: 1
        $x_1_2 = "bJanuarytypicallypatch4data" ascii //weight: 1
        $x_1_3 = "zESecurityqOn" ascii //weight: 1
        $x_1_4 = "xGoogleoQtheuaFebruary0browser" ascii //weight: 1
        $x_1_5 = "raawpublished0OperaJavaScript" ascii //weight: 1
        $x_1_6 = "tipsQPCwhowelcome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GB_2147748139_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GB!MTB"
        threat_id = "2147748139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 8a 1c 12 45 28 cb 48 8b 54 24 ?? 44 8a 4c 24 ?? 44 88 8c 24 [0-4] 4c 29 c1 8b 44 24 ?? 0f af c0 89 84 24 [0-4] 4c 8b 44 24 48 45 88 1c 10 48 03 4c 24 ?? 66 8b 74 24 ?? 66 29 f6 66 89 b4 24 [0-4] 48 8b 94 24 [0-4] 48 89 4c 24 ?? 48 39 d1 0f 85}  //weight: 10, accuracy: Low
        $x_10_2 = {89 c1 48 8d 15 [0-4] 8b 44 24 ?? 89 84 24 [0-4] 4c 8b 44 24 ?? 44 8a 4c 24 ?? 41 80 f1 ff}  //weight: 10, accuracy: Low
        $x_1_3 = "raisingn587" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GC_2147749194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GC!MTB"
        threat_id = "2147749194"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 8a 0a 48 81 c1 ?? ?? ?? ?? 44 8a 54 24 ?? 41 80 e2 ?? 44 88 54 24 ?? 89 44 24 2c 48 8b 54 24 ?? 46 8a 14 02 45 28 ca 8b 44 24 ?? 05 ?? ?? ?? ?? 44 8b 5c 24 ?? 4c 8b 44 24 ?? 48 8b 74 24 ?? 46 88 14 06 48 89 4c 24 ?? 41 39 c3 0f 84}  //weight: 10, accuracy: Low
        $x_1_2 = "aincluding1p" ascii //weight: 1
        $x_1_3 = "raisingn587" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GC_2147749194_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GC!MTB"
        threat_id = "2147749194"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C4crashtoKTPagegodzillasl" ascii //weight: 1
        $x_1_2 = "TreleasedLeakedfChrome" ascii //weight: 1
        $x_1_3 = "toBDebiansandboxingAdandzH5" ascii //weight: 1
        $x_1_4 = "KincludingwebsitesYson4iw" ascii //weight: 1
        $x_1_5 = "refreshcancelstatedtrustno1heWhileand" ascii //weight: 1
        $x_1_6 = "WbSyankee4notthomasin" ascii //weight: 1
        $x_1_7 = "Mupdates.92thethedaxztheopened" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win64_Dridex_SA_2147750271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.SA!MSR"
        threat_id = "2147750271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ads1ChromeB" wide //weight: 1
        $x_1_2 = "Chrome17asksZIremoved" wide //weight: 1
        $x_1_3 = "LockWindowUpdate" ascii //weight: 1
        $x_1_4 = "cactus-riddencode" wide //weight: 1
        $x_1_5 = "TraceMonkey" ascii //weight: 1
        $x_1_6 = "fitoWusedChrome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_SB_2147750345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.SB!MSR"
        threat_id = "2147750345"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "refersChromiumFlash" wide //weight: 1
        $x_1_2 = "BeachatoGoogle" wide //weight: 1
        $x_5_3 = "T+igHp*2cyuq$BM" wide //weight: 5
        $x_5_4 = "KYdj?T+igHp*2cyuq$BM" wide //weight: 5
        $x_1_5 = "GetUserDefaultLocaleName" ascii //weight: 1
        $x_1_6 = "Jupofblocked" ascii //weight: 1
        $x_1_7 = "ModifyExecuteProtectionSupport" ascii //weight: 1
        $x_1_8 = "TrackPopupMenu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Dridex_GK_2147751549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GK!MTB"
        threat_id = "2147751549"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 81 ec c8 00 00 00 48 8d 05 bb 70 02 00 41 b8 ?? ?? ?? ?? 4c 8d 8c 24 80 00 00 00 44 8b 94 24 a4 00 00 00 c7 84}  //weight: 2, accuracy: Low
        $x_1_2 = {d8 e1 e9 40 62 f4 64 56 9f 17 1a 47 6f c4 11 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_SC_2147751963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.SC!MSR"
        threat_id = "2147751963"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lifehack" ascii //weight: 1
        $x_1_2 = "importanthentai" ascii //weight: 1
        $x_1_3 = "loveremoved" ascii //weight: 1
        $x_1_4 = "SquirrelFishChromescript" ascii //weight: 1
        $x_1_5 = "Sandbox" wide //weight: 1
        $x_1_6 = "37toGOg78inscoresqbubba" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_MR_2147765415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.MR!MTB"
        threat_id = "2147765415"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kernel51.dll" ascii //weight: 1
        $x_1_2 = "dpamnlrd.pdb" ascii //weight: 1
        $x_1_3 = "Apple Computer, Inc." wide //weight: 1
        $x_1_4 = "GetPrivateProfileStringW" ascii //weight: 1
        $x_1_5 = "DebugActiveProcess" ascii //weight: 1
        $x_1_6 = "DecryptFileW" ascii //weight: 1
        $x_1_7 = "CoreVideo" wide //weight: 1
        $x_1_8 = "LookupAccountSidA" ascii //weight: 1
        $x_1_9 = "kernel32ntdll.dl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_2147766776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.MT!MTB"
        threat_id = "2147766776"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 04 24 48 8b 4c 24 ?? 66 8b 54 24 ?? 66 0f af d2 48 81 c1 ?? ?? ?? ?? 66 89 54 24 ?? 4c 8b 44 24 ?? 45 8a 0c 00 4c 8b 54 24 ?? 45 88 0c 02 c7 44 24 ?? ?? ?? ?? ?? 48 01 c8 48 8b 4c 24 ?? 48 39 c8 48 89 04 24 74 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 44 24 ?? 48 35 ?? ?? ?? ?? 66 8b 4c 24 ?? 66 69 d1 ?? ?? 66 89 54 24 ?? 44 8a 44 24 ?? 4c 8b 4c 24 ?? 45 88 01 48 03 44 24 ?? c6 44 24 5b ?? 48 89 44 24 ?? 44 8a 44 24 ?? 41 80 f0 ?? 44 88 44 24 ?? 4c 8b 4c 24 ?? 4c 39 c8 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 04 24 8b 4c 24 ?? 48 8b 54 24 ?? 89 4c 24 ?? 4c 8b 44 24 ?? 45 8a 0c 00 48 81 f2 ?? ?? ?? ?? 4c 8b 54 24 ?? 45 88 0c 02 48 01 d0 48 8b 54 24 ?? 48 39 d0 48 89 04 24 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Dridex_MY_2147770162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.MY!MTB"
        threat_id = "2147770162"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 24 66 8b [0-3] 66 89 [0-3] 8a [0-3] 44 8a [0-3] 41 80 [0-3] 44 88 [0-3] 28 d0 4c 8b [0-3] 4d 21 c9 8a [0-3] 4c 89 [0-3] 4c 8b [0-3] 4c 89 [0-3] 38 d0 0f 87 [0-4] e9}  //weight: 1, accuracy: Low
        $x_1_2 = {66 8b 44 24 ?? 66 35 [0-3] 8b [0-3] 66 89 [0-3] 81 f1 [0-4] 8b [0-3] 89 [0-3] 44 8b [0-3] 44 8a [0-3] 41 80 [0-3] 44 88 [0-3] 41 39 c8 77 c8 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Dridex_MZ_2147770332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.MZ!MTB"
        threat_id = "2147770332"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fBGT.pdb" ascii //weight: 1
        $x_1_2 = "neler6.dll" ascii //weight: 1
        $x_1_3 = "Secur32.dll" ascii //weight: 1
        $x_1_4 = "FloodFill" ascii //weight: 1
        $x_1_5 = "CRYPT32.dll" ascii //weight: 1
        $x_1_6 = "g_rgSCardT1Pci" ascii //weight: 1
        $x_1_7 = "WinSCard.dll" ascii //weight: 1
        $x_1_8 = "WtcdHiqeg.qtx" wide //weight: 1
        $x_1_9 = "oInECanaryyitChrome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win64_Dridex_ALE_2147781342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ALE!MTB"
        threat_id = "2147781342"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "fprolg76" ascii //weight: 3
        $x_3_2 = "sdmf|er.pdb" ascii //weight: 3
        $x_3_3 = "raisingn587" ascii //weight: 3
        $x_3_4 = "aincluding1p" ascii //weight: 3
        $x_3_5 = "SHPathPrepareForWriteW" ascii //weight: 3
        $x_3_6 = "CryptCATGetCatAttrInfo" ascii //weight: 3
        $x_3_7 = "midiOutCachePatches" ascii //weight: 3
        $x_3_8 = "SCardReleaseContext" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_SB_2147781538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.SB!MTB"
        threat_id = "2147781538"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rmi#dRf.pdb" ascii //weight: 3
        $x_3_2 = "j29,Googles5EjPh" ascii //weight: 3
        $x_3_3 = "vkgBiggerxversion" ascii //weight: 3
        $x_3_4 = "PgIFacebook,containerswhenNinterruptQover" ascii //weight: 3
        $x_3_5 = "Yauto-update5" ascii //weight: 3
        $x_3_6 = "Pscscripted23.98n" ascii //weight: 3
        $x_3_7 = "4.0NmZbrowserst" ascii //weight: 3
        $x_3_8 = "could2eBugsKdevelopers,z9" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_SB_2147781538_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.SB!MTB"
        threat_id = "2147781538"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rmi#dRf.pdb" ascii //weight: 3
        $x_3_2 = "g7KtheaZLthe" ascii //weight: 3
        $x_3_3 = "qzsoheatherdefault.thanhatake" ascii //weight: 3
        $x_3_4 = "voyagerqRtoWs" ascii //weight: 3
        $x_3_5 = "ChromeexplainedMNyicemanreliedsunshine" ascii //weight: 3
        $x_3_6 = "buildableyT" ascii //weight: 3
        $x_3_7 = "allPublic,12345Adallas" ascii //weight: 3
        $x_3_8 = "lprotocoltranslationl" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GW_2147782120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GW!MTB"
        threat_id = "2147782120"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {80 f3 ff 88 5c 24 ?? 8a 1c 30 88 5c 24 ?? 48 c7 44 24 ?? ?? ?? ?? ?? 4c 89 44 24 ?? 48 39 ca 0f 84 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
        $x_10_2 = {44 28 c2 66 44 8b 54 24 ?? 66 41 81 e2 ?? ?? 66 44 89 54 24 ?? 4c 8b 5c 24 ?? 43 88 14 0b 4c 8b 4c 24 ?? 49 81 f1 ?? ?? ?? ?? 4c 89 4c 24 ?? 48 03 44 24 ?? c7 44 24 78 ?? ?? ?? ?? 4c 8b 4c 24 ?? 8a 54 24 ?? 0a 54 24 ?? 88 54 24}  //weight: 10, accuracy: Low
        $x_1_3 = "FGT7t.pdb" ascii //weight: 1
        $x_1_4 = "TeltwFoo.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Dridex_GW_2147782120_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GW!MTB"
        threat_id = "2147782120"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 54 24 ?? 48 03 54 24 ?? 4c 8b 44 24 ?? 49 81 c0 ?? ?? ?? ?? 48 89 54 24 ?? 48 8b 54 24 ?? 48 83 f2 ff 49 89 c1 4d 21 c1 48 89 54 24 ?? 44 8b 54 24 ?? 45 69 da ?? ?? ?? ?? 42 8a 1c 09 44 89 5c 24 ?? c6 44 24 57}  //weight: 10, accuracy: Low
        $x_10_2 = {4c 8b 44 24 ?? 41 88 34 00 41 81 ea ?? ?? ?? ?? 44 89 54 24 ?? 48 01 d0 8a 5c 24 ?? 88 5c 24 ?? 48 8b 14 24 48 39 d0 48 89 44 24 ?? 0f 85}  //weight: 10, accuracy: Low
        $x_1_3 = "FGT7t.pdb" ascii //weight: 1
        $x_1_4 = "raisingn587" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GY_2147782371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GY!MTB"
        threat_id = "2147782371"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {42 8a 1c 1a 44 28 cb 48 2b 4c 24 ?? 4c 8b 44 24 ?? 43 88 1c 18 8b 44 24 ?? 0f af c0 89 44 24 ?? 49 01 cb 48 8b 4c 24 ?? 48 c7 44 24 ?? ?? ?? ?? ?? 41 b1 ?? 8a 44 24 ?? 41 f6 e1 88 44 24 ?? 4c 89 5c 24 ?? b0 6f 44 8a 4c 24 ?? 88 44 24 ?? 44 88 c8 8a 5c 24 ?? f6 e3 88 44 24 ?? 49 39 cb 0f 85}  //weight: 10, accuracy: Low
        $x_1_2 = "FGT7t.pdb" ascii //weight: 1
        $x_1_3 = "raisingn587" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_SA_2147782695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.SA!MTB"
        threat_id = "2147782695"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "raisingn587" ascii //weight: 3
        $x_3_2 = "aincluding1p" ascii //weight: 3
        $x_3_3 = "FGT7t.pdb" ascii //weight: 3
        $x_3_4 = "CryptImportPublicKeyInfo" ascii //weight: 3
        $x_3_5 = "oTZnioD" ascii //weight: 3
        $x_3_6 = "CRYPT32.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_PQ_2147783288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.PQ!MTB"
        threat_id = "2147783288"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 04 24 48 0d [0-4] 48 89 [0-3] 48 03 [0-3] 48 89 [0-3] 48 8b [0-3] 48 39 c1 0f 84 [0-4] e9 [0-4] b8 [0-4] 89 c1 48 2b [0-3] 48 89 [0-3] 8a [0-3] 80 [0-2] 88 [0-3] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GD_2147783526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GD!MTB"
        threat_id = "2147783526"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c1 8a 54 24 ?? 4c 8b 44 24 ?? 48 2b 4c 24 ?? 4c 8b 4c 24 ?? 43 88 14 01 c7 84 24 [0-8] 4c 8b 44 24 ?? 48 03 4c 24 ?? 8a 54 24 17 80 c2 ?? 88 94 24 [0-4] 8b 04 24 89 84 24 [0-4] 48 89 4c 24 ?? 4c 39 c1 75}  //weight: 10, accuracy: Low
        $x_10_2 = {44 88 84 24 [0-4] 48 8b 54 24 ?? 4c 8b 54 24 ?? 4c 89 94 24 [0-4] 4c 8b 5c 24 ?? 44 8a 04 08 48 8b 44 24 ?? 42 8a 1c 18 8b 34 24 81 f6 [0-4] 89 b4 24 [0-4] 44 28 c3 88 5c 24 ?? 49 39 d1 0f 82}  //weight: 10, accuracy: Low
        $x_1_3 = "aincluding1p" ascii //weight: 1
        $x_1_4 = "raisingn587" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_B_2147783531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.B!MTB"
        threat_id = "2147783531"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {49 81 f1 b9 74 b6 60 4c 8b 15 3d 3e 00 00 ba 7e d6 44 00 89 d6 48 89 4c 24 60 48 89 f1 4c 89 ca 48 89 44 24 58 41 ff d2 48 8d 8c 24 c0 00 00 00 48 8b 54 24 68 48 81 fa 95 e2 c4 62 89 44 24 54 48 89 4c 24 48}  //weight: 10, accuracy: High
        $x_3_2 = "KillTimer" ascii //weight: 3
        $x_3_3 = "EndDeferWindowPos" ascii //weight: 3
        $x_3_4 = "RpcImpersonateClient" ascii //weight: 3
        $x_3_5 = "OemToCharBuffW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_S_2147783532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.S!MTB"
        threat_id = "2147783532"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "raisingn587" ascii //weight: 3
        $x_3_2 = "aincluding1p" ascii //weight: 3
        $x_3_3 = "ccpler.pdb" ascii //weight: 3
        $x_3_4 = "SetICMMode" ascii //weight: 3
        $x_3_5 = "NdrClearOutParameters" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ME_2147783533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ME!MTB"
        threat_id = "2147783533"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ppR6|MJ.pdb" ascii //weight: 3
        $x_3_2 = "HwBvKwasGbitchesZP" ascii //weight: 3
        $x_3_3 = "oInECanaryyitChrome" ascii //weight: 3
        $x_3_4 = "barbeta),byroughly" ascii //weight: 3
        $x_3_5 = "RemoveDirectoryA" ascii //weight: 3
        $x_3_6 = "GetTimeFormatW" ascii //weight: 3
        $x_3_7 = "PathRemoveArgsW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_MD_2147783534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.MD!MTB"
        threat_id = "2147783534"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "xpb.pdb" ascii //weight: 3
        $x_3_2 = "GetUrlCacheEntryInfoA" ascii //weight: 3
        $x_3_3 = "CM_Get_Sibling_Ex" ascii //weight: 3
        $x_3_4 = "SaferCreateLevel" ascii //weight: 3
        $x_3_5 = "raisingn587" ascii //weight: 3
        $x_3_6 = "aincluding1p" ascii //weight: 3
        $x_3_7 = "GetSaveFileNameA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_MV_2147783542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.MV!MTB"
        threat_id = "2147783542"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "sdmf|er.pdb" ascii //weight: 3
        $x_3_2 = "UnenableRouter" ascii //weight: 3
        $x_3_3 = "GetRTTAndHopCount" ascii //weight: 3
        $x_3_4 = "PathIsUNCServerShareW" ascii //weight: 3
        $x_3_5 = "vulnerabilities.congratulatedPlayer.reasoningARuraSisb" ascii //weight: 3
        $x_3_6 = "DsEnumerateDomainTrustsW" ascii //weight: 3
        $x_3_7 = "GetUrlCacheEntryInfoA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_PS_2147783566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.PS!MTB"
        threat_id = "2147783566"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 89 ca 45 21 c2 45 89 d0 45 89 c3 42 8a [0-2] 66 8b [0-3] 66 81 [0-3] 66 89 [0-3] 48 8b [0-2] 48 81 [0-5] 44 8b [0-3] 48 89 [0-3] 44 29 ?? c6 [0-4] 45 89 ?? 44 89 ?? 44 8b [0-3] 41 81 [0-5] 4c 8b [0-3] 41 8a [0-2] 44 89 [0-3] 40 28 ?? 48 8b [0-3] 40 88 [0-2] 41 01 ?? 44 89 [0-3] 8b [0-3] 41 39 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AS_2147783680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AS!MTB"
        threat_id = "2147783680"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c2 b9 40 00 00 00 83 e0 3f 2b c8 33 c0 48 d3 c8 b9 20 00 00 00 48 33 c2 f3 48 ab 48 8b 7c 24 08 b0 01 c3}  //weight: 10, accuracy: High
        $x_10_2 = {41 8b c2 b9 40 00 00 00 83 e0 3f 2b c8 48 d3 cf 49 33 fa 4b 87 bc f7 00 ca 09}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AS_2147783680_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AS!MTB"
        threat_id = "2147783680"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FGT7t.pdb" ascii //weight: 3
        $x_3_2 = "SetICMMode" ascii //weight: 3
        $x_3_3 = "NdrClearOutParameters" ascii //weight: 3
        $x_3_4 = "raisingn587" ascii //weight: 3
        $x_3_5 = "aincluding1p" ascii //weight: 3
        $x_3_6 = "LdrGetProcedureAddress" ascii //weight: 3
        $x_3_7 = "GDI32.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_PT_2147783762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.PT!MTB"
        threat_id = "2147783762"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 e3 88 44 [0-2] 8b [0-3] 41 89 ?? 44 89 ?? c7 [0-7] 66 8b [0-3] 66 29 ?? 4c 8b [0-3] 41 8a [0-2] 40 28 ?? 44 8b [0-3] 66 89 [0-3] 66 8b [0-3] 66 83 [0-2] 41 81 [0-5] 66 89 [0-3] 4c 8b [0-3] 41 88 [0-2] 44 01 ?? 8a [0-3] 88 [0-3] 66 8b [0-3] 66 81 [0-3] 66 89 [0-3] 44 8b [0-3] 44 39 ?? 89 ?? ?? ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AK_2147783767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AK!MTB"
        threat_id = "2147783767"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DDTBG.pdb" ascii //weight: 3
        $x_3_2 = "SaferCreateLevel" ascii //weight: 3
        $x_3_3 = "CM_Get_Sibling_Ex" ascii //weight: 3
        $x_3_4 = "GetUrlCacheEntryInfoW" ascii //weight: 3
        $x_3_5 = "raisingn587" ascii //weight: 3
        $x_3_6 = "aincluding1p" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AK_2147783767_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AK!MTB"
        threat_id = "2147783767"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LOGONSERVER" ascii //weight: 3
        $x_3_2 = "discordapp" ascii //weight: 3
        $x_3_3 = "gay_nigger_porn" ascii //weight: 3
        $x_3_4 = "HelloWorldXll.pdb" ascii //weight: 3
        $x_3_5 = "ShellExecuteExW" ascii //weight: 3
        $x_3_6 = "URLDownloadToFileW" ascii //weight: 3
        $x_3_7 = "DirSyncScheduleDialog" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win64_Dridex_AH_2147783881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AH!MTB"
        threat_id = "2147783881"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "sdmf|er.pdb" ascii //weight: 3
        $x_3_2 = "Cyu:-#!" ascii //weight: 3
        $x_3_3 = "raisingn587" ascii //weight: 3
        $x_3_4 = "aincluding1p" ascii //weight: 3
        $x_3_5 = "fprolg76._l" ascii //weight: 3
        $x_3_6 = "VkKeyScanA" ascii //weight: 3
        $x_3_7 = "CryptCATClose" ascii //weight: 3
        $x_3_8 = "OpenPersonalTrustDBDialog" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win64_Dridex_AI_2147783882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AI!MTB"
        threat_id = "2147783882"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Fbnmvl.pdb" ascii //weight: 3
        $x_3_2 = "U6m#R6m" ascii //weight: 3
        $x_3_3 = "raisingn587" ascii //weight: 3
        $x_3_4 = "aincluding1p" ascii //weight: 3
        $x_3_5 = "NdrClearOutParameters" ascii //weight: 3
        $x_3_6 = "SetICMMode" ascii //weight: 3
        $x_3_7 = "%R: p3" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GE_2147783931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GE!MTB"
        threat_id = "2147783931"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 81 f3 00 b7 85 15 41 28 c0 48 89 8c 24 ?? ?? ?? ?? 48 8b b4 24 ?? ?? ?? ?? 48 c7 84 24 ?? ?? ?? ?? 1a 19 af 51 44 88 84 34 ?? ?? ?? ?? 48 21 c9 48 89 8c 24 ?? ?? ?? ?? 4c 03 9c 24 ?? ?? ?? ?? 4c 89 5c 24 ?? 49 39 d3 0f 84}  //weight: 10, accuracy: Low
        $x_1_2 = "K5nlnot" ascii //weight: 1
        $x_1_3 = "rrpiode.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GE_2147783931_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GE!MTB"
        threat_id = "2147783931"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 44 24 ?? 45 89 c2 44 89 d2 44 8b 44 24 ?? 44 8b 4c 24 ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 0f af c9 4c 89 8c 24 ?? ?? ?? ?? 45 89 d2 45 89 d1 48 89 54 24 ?? 4c 89 ca 45 89 d9 ff d0}  //weight: 1, accuracy: Low
        $x_10_3 = "aincluding1p" ascii //weight: 10
        $x_10_4 = "raisingn587" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Dridex_PV_2147784005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.PV!MTB"
        threat_id = "2147784005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 24 47 24 ?? 88 [0-6] 8b [0-6] 48 8b [0-3] 48 83 [0-2] 48 89 [0-6] 81 [0-5] 48 8b [0-8] 2a [0-3] 48 8b [0-3] 4c 8b [0-3] 41 88 [0-2] 03 [0-6] 89 [0-6] 8a [0-5] 88 [0-6] 44 8b [0-5] c9 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GF_2147784088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GF!MTB"
        threat_id = "2147784088"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 d9 44 89 44 24 ?? 41 89 c0 44 89 54 24 ?? e8 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? 48 8b 54 24 ?? 48 81 ca ?? ?? ?? ?? 48 89 94 24 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_10_2 = "aincluding1p" ascii //weight: 10
        $x_10_3 = "raisingn587" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DB_2147784161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DB!MTB"
        threat_id = "2147784161"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BofforZindashes" ascii //weight: 3
        $x_3_2 = "zWvMayentersto2012,althoughNew" ascii //weight: 3
        $x_3_3 = "wpluginsmarketqonrecursion-tracingj" ascii //weight: 3
        $x_3_4 = "777777778Jbrowsers.624" ascii //weight: 3
        $x_3_5 = "FindFirstUrlCacheEntryW" ascii //weight: 3
        $x_3_6 = "InitiateSystemShutdownW" ascii //weight: 3
        $x_3_7 = "GetSidLengthRequired" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_PW_2147784700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.PW!MTB"
        threat_id = "2147784700"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f2 4c 8b [0-3] 49 81 [0-5] 4c 89 [0-3] 4c [0-4] 41 8a [0-2] 28 d8 48 8b [0-3] 48 89 [0-3] 4c 8b [0-3] 41 88 [0-2] 66 8b [0-3] 66 81 [0-3] 66 89 [0-3] 45 01 ?? 66 c7 [0-5] 44 89 [0-3] 48 29 ?? 48 89 [0-3] 44 8b [0-3] 45 39 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DC_2147784827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DC!MTB"
        threat_id = "2147784827"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "sdmf|er.pdb" ascii //weight: 3
        $x_3_2 = "CryptImportPublicKeyInfo" ascii //weight: 3
        $x_3_3 = "raisingn587" ascii //weight: 3
        $x_3_4 = "aincluding1p" ascii //weight: 3
        $x_3_5 = "LdrGetProcedureAddress" ascii //weight: 3
        $x_3_6 = "CRYPT32.dll" ascii //weight: 3
        $x_3_7 = "X6mo4:" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DK_2147785056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DK!MTB"
        threat_id = "2147785056"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4c 8b d9 0f b6 d2 49 b9 01 01 01 01 01 01 01 01 4c 0f af ca 49 83 f8 10 0f 86 f2 00 00 00 66 49 0f 6e c1 66 0f 60 c0 49 81 f8 80 00 00 00 77 10}  //weight: 10, accuracy: High
        $x_10_2 = {48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 10 40 8a 3a 48 8b da 4c 8b c1 40 84 ff}  //weight: 10, accuracy: High
        $x_3_3 = "kdtltdybip" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DK_2147785056_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DK!MTB"
        threat_id = "2147785056"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 83 ec 38 c7 44 24 30 de 9b 91 43 66 8b 44 24 36 66 83 f0 ff 66 89 44 24 36 e8 41 fa ff ff b9 01 00 00 00 ba 3c 93 29 67 41 89 d0 4c 2b 44 24 28 8b 54 24 30 81 c2 22 64 6e bc 4c 89 44 24 28 39 d0 89 4c 24 24}  //weight: 10, accuracy: High
        $x_3_2 = "StrTrimW" ascii //weight: 3
        $x_3_3 = "UrlUnescapeA" ascii //weight: 3
        $x_3_4 = "MprAdminInterfaceTransportAdd" ascii //weight: 3
        $x_3_5 = "GetUrlCacheEntryInfoW" ascii //weight: 3
        $x_3_6 = "HICON_UserMarshal" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DK_2147785056_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DK!MTB"
        threat_id = "2147785056"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "likewelcomebrowserA" ascii //weight: 3
        $x_3_2 = "37toGOg78inscoresqbubba" ascii //weight: 3
        $x_3_3 = "VLincludedtheReleaseand32009,bereceiving" ascii //weight: 3
        $x_3_4 = "CM_Get_Resource_Conflict_DetailsW" ascii //weight: 3
        $x_3_5 = "CertGetCTLContextProperty" ascii //weight: 3
        $x_3_6 = "Iw6which9iU1%h" ascii //weight: 3
        $x_3_7 = "DeleteCriticalSection" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AY_2147786453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AY!MTB"
        threat_id = "2147786453"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "9MOYcn5MdYeS4YEM" ascii //weight: 3
        $x_3_2 = "doNUNybUJYFECYVS" ascii //weight: 3
        $x_3_3 = "IsProcessorFeaturePresent" ascii //weight: 3
        $x_3_4 = "RtlLookupFunctionEntry" ascii //weight: 3
        $x_3_5 = "CommandLineToArgvW" ascii //weight: 3
        $x_3_6 = "BoxedAppSDK_CreateVirtualFileA" ascii //weight: 3
        $x_3_7 = "Discord helper" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DM_2147786457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DM!MTB"
        threat_id = "2147786457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "sdmf|er.pdb" ascii //weight: 3
        $x_3_2 = "CryptImportPublicKeyInfo" ascii //weight: 3
        $x_3_3 = "#RleaoP>dt" ascii //weight: 3
        $x_3_4 = "raisingn587" ascii //weight: 3
        $x_3_5 = "aincluding1p" ascii //weight: 3
        $x_3_6 = "LdrGet" ascii //weight: 3
        $x_3_7 = "VirtualAlloc" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DM_2147786457_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DM!MTB"
        threat_id = "2147786457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ddgh33d\\" ascii //weight: 3
        $x_3_2 = "VG234v5234" ascii //weight: 3
        $x_3_3 = "WriteFileEx" ascii //weight: 3
        $x_3_4 = "IsProcessInJob" ascii //weight: 3
        $x_3_5 = "MprConfigInterfaceTransportGetInfo" ascii //weight: 3
        $x_3_6 = "CM_Get_Device_Interface_List_SizeW" ascii //weight: 3
        $x_3_7 = "HttpAddRequestHeadersW" ascii //weight: 3
        $x_3_8 = "KillTimer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DV_2147786528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DV!MTB"
        threat_id = "2147786528"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FGT7t.pdb" ascii //weight: 3
        $x_3_2 = "CryptAcquireCertificatePrivateKey" ascii //weight: 3
        $x_3_3 = "heon6$" ascii //weight: 3
        $x_3_4 = "6wUvxqUv" ascii //weight: 3
        $x_3_5 = "raisingn587" ascii //weight: 3
        $x_3_6 = "aincluding1p" ascii //weight: 3
        $x_3_7 = "R.\\yQZNtyoof" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GI_2147786538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GI!MTB"
        threat_id = "2147786538"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 31 c0 44 89 c1 44 8b 44 24 ?? 45 89 c1 44 89 ca 44 8b 44 24 ?? 44 8b 4c 24 ?? ff d0}  //weight: 10, accuracy: Low
        $x_10_2 = {e6 2f 44 8b 84 24 [0-4] 44 8b 8c 24 [0-4] 41 81 c0 c7 a3 49 b0 44 29 c8 48 89 4c 24 60 89 44 24 5c e8 [0-4] 8b 84 24 [0-4] 05 b9 b3 49 b0 c6 84 24 [0-4] ?? 48 8b 4c 24 ?? 89 44 24 ?? e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GI_2147786538_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GI!MTB"
        threat_id = "2147786538"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 29 f1 41 81 f3 30 1b e3 01 48 89 8c 24 ?? ?? ?? ?? 8b bc 24 ?? ?? ?? ?? 81 c7 cc f4 1c fe 4c 89 c9 41 89 c0 44 89 5c 24 ?? 89 7c 24 ?? e8 ?? ?? ?? ?? 8a 5c 24 ?? 80 c3 ?? 88 9c 24 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
        $x_10_2 = {44 8b 9c 24 ?? ?? ?? ?? 45 89 d9 66 c7 84 24 ?? ?? ?? ?? ?? ?? 48 89 54 24 ?? 4c 89 ca 44 8b 5c 24 ?? 44 89 44 24 ?? 45 89 d8 44 8b 4c 24 ?? ff d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DH_2147787012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DH!MTB"
        threat_id = "2147787012"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ppR6|MJ.pdb" ascii //weight: 3
        $x_3_2 = "vulnerabilitiesIOctoberMbecamePlExample:will25," ascii //weight: 3
        $x_3_3 = "badboyIreleasehasEinspectorXofAcid1Automatic" ascii //weight: 3
        $x_3_4 = "ChromepLpgthereafter,supportedcheesewhile" ascii //weight: 3
        $x_3_5 = "JetMakeKey" ascii //weight: 3
        $x_3_6 = "Frecognition.Alternatively,beforeOQQ" ascii //weight: 3
        $x_3_7 = "tyharsenal112233" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ALH_2147787014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ALH!MTB"
        threat_id = "2147787014"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "sdmf|er.pdb" ascii //weight: 3
        $x_3_2 = "CryptImportPublicKeyInfo" ascii //weight: 3
        $x_3_3 = "raisingn587" ascii //weight: 3
        $x_3_4 = "aincluding1p" ascii //weight: 3
        $x_3_5 = "LdrGetProcedureAddress" ascii //weight: 3
        $x_3_6 = "VirtualAlloc" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ALK_2147787015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ALK!MTB"
        threat_id = "2147787015"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "benchmarks,fromHvotherthem.2989.75%Resig,the" ascii //weight: 3
        $x_3_2 = "t42.0.2311.4maderChromeyankeeTnthe" ascii //weight: 3
        $x_3_3 = "startingqandvisitedGZ9876545555554" ascii //weight: 3
        $x_3_4 = "GetClusterResourceNetworkName" ascii //weight: 3
        $x_3_5 = "Gvoandin2018,YboxjackieY" ascii //weight: 3
        $x_3_6 = "LookupAccountSidA" ascii //weight: 3
        $x_3_7 = "FindFirstFreeAce" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AMT_2147787016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AMT!MTB"
        threat_id = "2147787016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ef c0 f3 0f 7f 44 24 70 66 0f 6e ca 99 66 0f 62 d1 f3 0f 7f 94 24 80 00 00 00 66 0f 6e da 66 0f 62 e3 f3 0f 7f a4 24 90}  //weight: 10, accuracy: High
        $x_3_2 = "AddLookaside" ascii //weight: 3
        $x_3_3 = "CreateDesktopAppXActivationInfo" ascii //weight: 3
        $x_3_4 = "4cH03" ascii //weight: 3
        $x_3_5 = "CloseAppExecutionAlias" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AMK_2147787040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AMK!MTB"
        threat_id = "2147787040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b8 6f 8d 0d 00 89 04 24 89 44 24 04 8b 04 24 03 44 24 04 69 d0 ab aa aa aa 81 c2 aa aa aa 2a 8b 04 24 81 fa 55 55 55 55 72 64 05 9b 66 25 02}  //weight: 10, accuracy: High
        $x_3_2 = "duier" ascii //weight: 3
        $x_3_3 = "glopiq" ascii //weight: 3
        $x_3_4 = "jpqdr" ascii //weight: 3
        $x_3_5 = "GetCurrentThreadId" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ACD_2147787470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ACD!MTB"
        threat_id = "2147787470"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c9 e7 70 80 e3 a5 83 15 2e 59 43 9a 38 f7 ac b7 32 f0 ac b3 e3 7a 5c bf c2 e0 fc 6c 0e cd d9 71}  //weight: 10, accuracy: High
        $x_3_2 = "MprAdminInterfaceTransportAdd" ascii //weight: 3
        $x_3_3 = "NdrUserMarshalUnmarshall" ascii //weight: 3
        $x_3_4 = "RpcBindingSetAuthInfoA" ascii //weight: 3
        $x_3_5 = "GetUrlCacheEntryInfoW" ascii //weight: 3
        $x_3_6 = "HICON_UserMarshal" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ACL_2147787471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ACL!MTB"
        threat_id = "2147787471"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e2 71 29 c7 7b 56 9d fa b4 46 08 4b 3e e4 b5 43 97 5b 4c 29 d3 83 6f 0a 35 b2 5d 94 a2 a7 6d ba}  //weight: 10, accuracy: High
        $x_3_2 = "UuidIsNil" ascii //weight: 3
        $x_3_3 = "CryptCATPutAttrInfo" ascii //weight: 3
        $x_3_4 = "CopyEnhMetaFileW" ascii //weight: 3
        $x_3_5 = "CreateDiscardableBitmap" ascii //weight: 3
        $x_3_6 = "UrlUnescapeA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ACL_2147787471_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ACL!MTB"
        threat_id = "2147787471"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d0 e8 f2 ff ff ff 33 00 4c 31 25 ?? ?? ?? ?? 48 31 15 ?? ?? ?? ?? 48 31 25 ?? ?? ?? ?? 48 31 1d ?? ?? ?? ?? 4c 31 0d ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? eb 09 4c 31 2d}  //weight: 10, accuracy: Low
        $x_3_2 = "GetUrlCacheEntryInfoW" ascii //weight: 3
        $x_3_3 = "AssociateColorProfileWithDeviceW" ascii //weight: 3
        $x_3_4 = "CryptCATPutAttrInfo" ascii //weight: 3
        $x_3_5 = "StrTrimW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DG_2147787525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DG!MTB"
        threat_id = "2147787525"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {46 46 c7 45 67 4c 5f 6e 5d 3d 11 d2 7b 1e af 21 a6 db b9 03 76 e2 69 42 4a 8f 10 ab fd 64 b7 da}  //weight: 10, accuracy: High
        $x_3_2 = "SetupDiSetSelectedDriverA" ascii //weight: 3
        $x_3_3 = "MprAdminInterfaceTransportAdd" ascii //weight: 3
        $x_3_4 = "UrlUnescapeA" ascii //weight: 3
        $x_3_5 = "StrTrimW" ascii //weight: 3
        $x_3_6 = "HICON_UserMarshal" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DG_2147787525_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DG!MTB"
        threat_id = "2147787525"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "@walkerareplacedAunanimouslysnM" ascii //weight: 3
        $x_3_2 = "into58websites" ascii //weight: 3
        $x_3_3 = "GetWindowsAccountDomainSid" ascii //weight: 3
        $x_3_4 = "GetUserNameA" ascii //weight: 3
        $x_3_5 = "LookupAccountSidW" ascii //weight: 3
        $x_3_6 = "GetCurrentHwProfileW" ascii //weight: 3
        $x_3_7 = "GetSecurityDescriptorOwner" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AJ_2147787528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AJ!MTB"
        threat_id = "2147787528"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ffpgglbm.pdb" ascii //weight: 3
        $x_3_2 = "yfamilyjbrowsersIron,9to3under" ascii //weight: 3
        $x_3_3 = "luckyincognitowasismarlboroe" ascii //weight: 3
        $x_3_4 = "theinsqseparately.d526,CSSRh" ascii //weight: 3
        $x_3_5 = "JBHcompany,player,can" ascii //weight: 3
        $x_3_6 = "sohidden89.75%Junenormal" ascii //weight: 3
        $x_3_7 = "boundaryfore3.0nversionsnews" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AGH_2147788054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AGH!MTB"
        threat_id = "2147788054"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "WBqthedanielle" ascii //weight: 3
        $x_3_2 = "didwbDbigdaddyweek" ascii //weight: 3
        $x_3_3 = "rmi#dRf.pdb" ascii //weight: 3
        $x_3_4 = "JetMakeKey" ascii //weight: 3
        $x_3_5 = "SCardGetCardTypeProviderNameW" ascii //weight: 3
        $x_3_6 = "InterlockedPushEntrySList" ascii //weight: 3
        $x_3_7 = "SetSystemTimeAdjustment" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AHB_2147788181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AHB!MTB"
        threat_id = "2147788181"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DFDD.pdb" ascii //weight: 3
        $x_3_2 = "CM_Get_Sibling_Ex" ascii //weight: 3
        $x_3_3 = "KF64-bitto4IncognitoIKinf" ascii //weight: 3
        $x_3_4 = "andapplicationsphishingZ2013,Store" ascii //weight: 3
        $x_3_5 = "zanThenowXr8" ascii //weight: 3
        $x_3_6 = "welcomegJVZpatch.O" ascii //weight: 3
        $x_3_7 = "URLotherWStableU6Mfailed11578the" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ABM_2147788954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ABM!MTB"
        threat_id = "2147788954"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "oCanary9dsupunderonbasedX" ascii //weight: 3
        $x_3_2 = "Nasthe39sChrome7Beta" ascii //weight: 3
        $x_3_3 = "KF64-bitto4IncognitoIKinf" ascii //weight: 3
        $x_3_4 = "K5nlnot" ascii //weight: 3
        $x_3_5 = "rrpiode.pdb" ascii //weight: 3
        $x_3_6 = "GetUrlCacheEntryInfoW" ascii //weight: 3
        $x_3_7 = "CreateDiscardableBitmap" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AHC_2147789092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AHC!MTB"
        threat_id = "2147789092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "nnxj2uq1" ascii //weight: 3
        $x_3_2 = "C:\\pointers.txt" ascii //weight: 3
        $x_3_3 = "System32\\drivers\\etc\\hosts" ascii //weight: 3
        $x_3_4 = "SELECT * FROM AntivirusProduct" ascii //weight: 3
        $x_3_5 = "DownloadAppendAsync" ascii //weight: 3
        $x_3_6 = "Q2hpbGthdEh0bWxUb1htbA==" ascii //weight: 3
        $x_3_7 = "Q2hpbGthdFNvY2tldA==" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AKN_2147792998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AKN!MTB"
        threat_id = "2147792998"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "K5nlnot" ascii //weight: 3
        $x_3_2 = "onupkreasoningChrome2RLZcInternet2008.28" ascii //weight: 3
        $x_3_3 = "rrpiode.pdb" ascii //weight: 3
        $x_3_4 = "bjaketuckerJinfromzG" ascii //weight: 3
        $x_3_5 = "MprAdminInterfaceTransportAdd" ascii //weight: 3
        $x_3_6 = "KF64-bitto4IncognitoIKinf" ascii //weight: 3
        $x_3_7 = "tCatart9dstpundtronttstdX" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AMQ_2147793332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AMQ!MTB"
        threat_id = "2147793332"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b9 01 00 00 00 8b 54 24 50 81 f2 5e db 74 39 4c 8b 44 24 40 4d 0f af c0 4c 89 44 24 58 39 d0 89 4c 24 30 74 09}  //weight: 10, accuracy: High
        $x_3_2 = "NetShareGetInfo" ascii //weight: 3
        $x_3_3 = "CryptCATPutAttrInfo" ascii //weight: 3
        $x_3_4 = "UrlUnescapeW" ascii //weight: 3
        $x_3_5 = "RpcBindingSetAuthInfoA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AA_2147793526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AA!MTB"
        threat_id = "2147793526"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 4c 24 20 48 8b 54 24 28 4c 8b 44 24 18 45 8a 0c 00 48 8b 44 24 08 44 88 0c 10 48 8b 54 24 28 48 83 c2 01 48 89 54 24 38 4c 8b 54 24 10 4c 39 d2}  //weight: 10, accuracy: High
        $x_10_2 = {83 e2 1f 89 d2 41 89 d0 8b 54 24 4c 89 54 24 4c 89 c2 41 89 d1 4c 8b 54 24 30 47 8a 1c 0a 46 2a 1c 01 48 8b 4c 24 20 46 88 1c 09}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_EF_2147794076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.EF!MTB"
        threat_id = "2147794076"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e9 b7 fd ff ff 31 00 48 89 15 ?? ?? ?? ?? 4c 89 05 ?? ?? ?? ?? 4c 89 0d ?? ?? ?? ?? 4c 89 25 ?? ?? ?? ?? 4c 89 2d ?? ?? ?? ?? 4c 89 35 ?? ?? ?? ?? 4c 89 3d}  //weight: 10, accuracy: Low
        $x_10_2 = {48 83 c1 01 89 94 24 88 00 00 00 48 89 4c 24 50 48 83 f9 25 89 44 24 3c 0f 84 ac 00 00 00 eb 46 8b 44 24 6c 0f af c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_EF_2147794076_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.EF!MTB"
        threat_id = "2147794076"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FGT7t.pdb" ascii //weight: 3
        $x_3_2 = "CryptImportPublicKeyInfo" ascii //weight: 3
        $x_3_3 = "raisingn587" ascii //weight: 3
        $x_3_4 = "aincluding1p" ascii //weight: 3
        $x_3_5 = "LdrGetProcedureAddress" ascii //weight: 3
        $x_3_6 = "CRYPT32.dll" ascii //weight: 3
        $x_3_7 = "VirtualAlloc" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_EC_2147794286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.EC!MTB"
        threat_id = "2147794286"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {45 32 f6 33 ff 42 8b 94 28 88 00 00 00 41 89 d2 46 8b 8c 28 8c 00 00 00 44 03 ca 43 8b 44 2a 20 47 8b 44 2a 24 49 03 c5 4d 03 c5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_EC_2147794286_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.EC!MTB"
        threat_id = "2147794286"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|ajgz&" ascii //weight: 1
        $x_1_2 = "rewertwer" ascii //weight: 1
        $x_1_3 = "n7345734m7345" ascii //weight: 1
        $x_1_4 = "LogonUserExW" ascii //weight: 1
        $x_1_5 = "isalnum" ascii //weight: 1
        $x_1_6 = "VirtualProtectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win64_Dridex_EC_2147794286_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.EC!MTB"
        threat_id = "2147794286"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rrpiode.pdb" ascii //weight: 3
        $x_3_2 = "GetNLSVersion" ascii //weight: 3
        $x_3_3 = "IcmpSendEcho2" ascii //weight: 3
        $x_3_4 = "malloc" ascii //weight: 3
        $x_3_5 = "OLEAUT32.dll" ascii //weight: 3
        $x_3_6 = "GetLastError" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_EC_2147794286_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.EC!MTB"
        threat_id = "2147794286"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rrpiode.pdb" ascii //weight: 3
        $x_3_2 = "onupkreasoningChrome2RLZcInternet2008.28" ascii //weight: 3
        $x_3_3 = "modefromAbrowser.YG" ascii //weight: 3
        $x_3_4 = "usageday,aCbacteriologyphoenixw" ascii //weight: 3
        $x_3_5 = "KF64-bitto4IncognitoIKinf" ascii //weight: 3
        $x_3_6 = "StrTrimW" ascii //weight: 3
        $x_3_7 = "GetUrlCacheEntryInfoW" ascii //weight: 3
        $x_3_8 = "CreateMetaFileA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_QQ_2147794583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.QQ!MTB"
        threat_id = "2147794583"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 8a 0c 08 89 54 24 4c 48 8b 44 24 18 46 8a 14 00 45 28 ca 48 8b 4c 24 08 46 88 14 01 8b 54 24 5c}  //weight: 10, accuracy: High
        $x_10_2 = {33 4c 24 24 89 4c 24 24 4c 8b 44 24 18 45 8a 0c 00 4c 8b 54 24 08 45 88 0c 02 48 8b 4c 24 28 48 d3 ea}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_QR_2147794689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.QR!MTB"
        threat_id = "2147794689"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 8c 24 48 01 00 00 48 89 f1 48 89 f7 48 d3 ef 48 89 bc 24 b0 04 00 00 4c 89 c9 49 89 f1 49 d3 e9 4c 89 8c 24 b0 04 00 00 8b 94 24 b8 04 00 00 89 d1 89 d3 d3 e3 89 9c 24 b8 04 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {88 4c 24 47 d3 ea 89 94 24 9c 01 00 00 89 c2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AQ_2147797774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AQ!MTB"
        threat_id = "2147797774"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 89 fa 45 01 ea 45 39 d3 72 02 eb 36 45 89 da 47 8a 14 16 44 88 55 cf 44 0f b6 55 cf 44 8b 4d bc 41 89 f0 45 01 c8 45 0f b6 c8 45 31 ca 44 88 55 cf 45 89 da 44 8a 4d cf 47 88 0c 16 4d 8d 5b 01}  //weight: 10, accuracy: High
        $x_10_2 = {4c 8b 55 90 4c 01 55 c0 4c 03 65 90 4c 8b 55 a0 4c 03 55 a8 49 83 ea 0a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AC_2147798148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AC!MTB"
        threat_id = "2147798148"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "pZ6r6KEICIOhhurPfmehzz.pdb" ascii //weight: 3
        $x_3_2 = "Girenderingmed4availablexxrelease" ascii //weight: 3
        $x_3_3 = "bloggersChromexOwasPN" ascii //weight: 3
        $x_3_4 = "RhFirefox,3OnOGoogleLt" ascii //weight: 3
        $x_3_5 = "Category:GooglecomputerJP" ascii //weight: 3
        $x_3_6 = "Explorer_Server" ascii //weight: 3
        $x_3_7 = "GetSecurityDescriptorGroup" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_AG_2147798232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.AG!MTB"
        threat_id = "2147798232"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "thewalkerz4bothNou" ascii //weight: 3
        $x_3_2 = "Category:GooglecomputerJP" ascii //weight: 3
        $x_3_3 = "0rExplorer3jPZ29,aby" ascii //weight: 3
        $x_3_4 = "RhFirefox,3OnOGoogleLt" ascii //weight: 3
        $x_3_5 = "bloggersChromexOwasPN" ascii //weight: 3
        $x_3_6 = "Girenderingmed4availablexxrelease" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_CW_2147799491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.CW!MTB"
        threat_id = "2147799491"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Explorer_Server" ascii //weight: 3
        $x_3_2 = "@internallyGbaraagainstq" ascii //weight: 3
        $x_3_3 = "WTwitter.altogether.112" ascii //weight: 3
        $x_3_4 = "sitesAdobeMTtravisvisitedGcowboyais" ascii //weight: 3
        $x_3_5 = "screeninInternet" ascii //weight: 3
        $x_3_6 = "minutes.292EcasualWebaccess" ascii //weight: 3
        $x_3_7 = "fromChrome9September9" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_QW_2147799572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.QW!MTB"
        threat_id = "2147799572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 45 d0 8a 08 8b 55 94 89 55 fc 48 8b 45 c0 49 89 c0 49 83 c0 01 4c 89 45 c0 44 8b 4d 98 41 81 c1 5e 0b 00 00 44 89 4d fc 88 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_QW_2147799572_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.QW!MTB"
        threat_id = "2147799572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 89 8c 24 e0 02 00 00 8a 94 24 df 02 00 00 44 8a 94 24 4f 02 00 00 80 c2 2d 88 84 24 f5 02 00 00}  //weight: 10, accuracy: High
        $x_3_2 = "Explorer_Server" ascii //weight: 3
        $x_3_3 = "testsvictoria4benchmarks,submissions" ascii //weight: 3
        $x_3_4 = "Chrome17asksZIremoved.wasyzA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_RPJ_2147805657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.RPJ!MTB"
        threat_id = "2147805657"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 88 1c 3a 03 8c 24 ?? ?? ?? ?? 66 44 8b 4c 24 ?? 66 41 83 f1 ?? 66 44 89 8c 24 ?? ?? ?? ?? 8b 94 24 ?? ?? ?? ?? 4c 8b 94 24 ?? ?? ?? ?? 4c 89 94 24 ?? ?? ?? ?? 89 8c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_QM_2147805721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.QM!MTB"
        threat_id = "2147805721"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rrpiode.pdb" ascii //weight: 3
        $x_3_2 = "onupkreasoningChrome2RLZcInternet2008.28" ascii //weight: 3
        $x_3_3 = "IcmpSendEcho2" ascii //weight: 3
        $x_3_4 = "bjaketuckerJinfromzG" ascii //weight: 3
        $x_3_5 = "ttY6Vpeovtduse" ascii //weight: 3
        $x_3_6 = "beAbigdickbeenUxspelling" ascii //weight: 3
        $x_3_7 = "bitto4IncognitoIKinf" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_QV_2147806179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.QV!MTB"
        threat_id = "2147806179"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 44 8b 9c 24 ce 01 00 00 44 89 ce 09 f6 89 b4 24 bc 01 00 00 4c 89 94 24 a0 01 00 00 8a 9c 24 bb 01 00 00 28 d9 49 89 c2 88 8c 24 bb 01 00 00 48 89 c1 4c 89 54 24 50 48 89 54 24 48 88 5c 24 47 4c 89 44 24 38 44 89 4c 24 34 66 44 89 5c 24 32}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_FD_2147808834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.FD!MTB"
        threat_id = "2147808834"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 4d 38 48 89 45 60 48 89 4d 00 48 8b 45 c0 48 89 45 60 48 8b 4d e8 8a 55 4b 88 11 8b 85 84 00 00 00 35 5e 52 00 00 8b 4d 2c 03 4d 2c 8b 55 5c 89 4d 2c 01 c2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_EB_2147809229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.EB!MTB"
        threat_id = "2147809229"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "hFofupdatesinto" ascii //weight: 3
        $x_3_2 = "Dv.29channel;" ascii //weight: 3
        $x_3_3 = "FGTRYYB.pdb" ascii //weight: 3
        $x_3_4 = "WintrustRemoveActionID" ascii //weight: 3
        $x_3_5 = "CryptGetDefaultProviderW" ascii //weight: 3
        $x_3_6 = "CreateScalableFontResourceA" ascii //weight: 3
        $x_3_7 = ".usedVyTheMLin" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_CE_2147809419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.CE!MTB"
        threat_id = "2147809419"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 83 ec 68 31 c0 89 c1 48 8b 54 24 60 c7 44 24 5c 77 d0 cb 62 8b 44 24 5c 66 44 8b 44 24 5a 66 44 89 44 24 5a 48 81 c2 c3 12 4e 1f 41 89 c1 41 81 c1 89 2f 34 9d 48 89 54 24 60 41 89 c2 41 81 ca 27 04 40 54 44 89 54 24 54}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DE_2147810888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DE!MTB"
        threat_id = "2147810888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 8b 54 24 50 44 2b 54 24 50 45 01 f1 45 21 c1 44 89 54 24 50 45 89 c8 44 89 c6 44 8a 1c 37 48 8b 74 24 30 44 32 1c 0e 44 8b 44 24 50 44 89 44 24 50 4c 8b 64 24 40 45 88 1c 0c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GTM_2147811348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GTM!MTB"
        threat_id = "2147811348"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MprAdminUserGetInfo" ascii //weight: 1
        $x_1_2 = "ckickickingckingngckickifufufufuckifuck" ascii //weight: 1
        $x_1_3 = "w,les83DfX*BXEnuybdCZV" ascii //weight: 1
        $x_1_4 = "1Wj>gpc+gG" ascii //weight: 1
        $x_1_5 = "^go/o@y]" ascii //weight: 1
        $x_1_6 = "MprAdminServerConnect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ZR_2147811991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ZR!MTB"
        threat_id = "2147811991"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PluginInit" ascii //weight: 1
        $x_1_2 = "RunObject" ascii //weight: 1
        $x_1_3 = "HuraCaxtcsbTsysl" ascii //weight: 1
        $x_1_4 = "JuotujMmgKhsnynzs" ascii //weight: 1
        $x_1_5 = "VmihevgEauykkanr" ascii //weight: 1
        $x_1_6 = "WhmnqagscmuFanedsrCowmbybtm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GZS_2147814241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GZS!MTB"
        threat_id = "2147814241"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 44 24 08 8b 4c 24 3c 89 4c 24 3c 48 8b 54 24 28 44 8a 04 02 4c 8b 4c 24 30 4c 89 4c 24 40 66 c7 44 24 4e ?? ?? 4c 8b 54 24 50 49 81 c2 ?? ?? ?? ?? 48 c7 44 24 40 ?? ?? ?? ?? 4c 8b 5c 24 18 45 88 04 03 4d 29 c9 4c 89 4c 24 40 4c 01 d0 69 4c 24 3c 3a 17 70 4d 89 4c 24 3c 8b 4c 24 3c 33 4c 24 3c 89 4c 24 3c 4c 8b 4c 24 20 4c 39 c8 48 89 44 24 08 74 10 eb 87}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_BB_2147817279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.BB!MTB"
        threat_id = "2147817279"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 8b 11 8b 44 24 4c 35 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 48 8b 4c 24 28 8b 41 1c 66 c7 84 24 ?? ?? ?? ?? af fd 44 0f b7 c2 45 89 c1}  //weight: 5, accuracy: Low
        $x_1_2 = "FGTRYYB.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DF_2147818494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DF!MTB"
        threat_id = "2147818494"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 04 24 48 8b 4c 24 28 48 81 c1 81 c5 dd a6 48 8b 54 24 18 44 8a 04 02 4c 8b 4c 24 08 45 88 04 01 66 44 8b 54 24 26 66 41 81 f2 93 a2 66 44 89 54 24 26 48 01 c8 48 8b 4c 24 10 48 39 c8 48 89 04 24 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ARA_2147836261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ARA!MTB"
        threat_id = "2147836261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 44 24 18 48 8b 4c 24 10 8a 14 01 4c 8b 04 24 41 88 14 00 48 83 c0 01 48 89 44 24 18 4c 8b 4c 24 08 4c 39 c8 75 d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_BD_2147836928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.BD!MTB"
        threat_id = "2147836928"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {42 8a 1c 3e 66 44 89 54 24 66 4c 8b 7c 24 28 4d 29 ff 44 30 cb 4c 89 7c 24 68 4c 8b 7c 24 50 43 88 1c 37 49 83 c6 01 4c 8b 24 24 4d 39 e6 8b 4c 24 0c 89 4c 24 18 89 54 24 1c 4c 89 74 24 20 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_BE_2147837081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.BE!MTB"
        threat_id = "2147837081"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 32 04 3a 8b 74 24 1c 89 74 24 6c 4c 8b 7c 24 38 43 88 04 37 4c 8b 64 24 10 4d 21 e4 49 83 c6 01 4c 89 64 24 60 4c 8b 64 24 58 4c 89 74 24 50 8b 7c 24 04 89 7c 24 44 89 54 24 48 66 8b 4c 24 6a 66 89 4c 24 6a 4d 39 e6 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_EM_2147842498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.EM!MTB"
        threat_id = "2147842498"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4c 24 34 89 ca 83 e2 1f 41 89 c8 45 89 c1 89 d2 41 89 d2 4c 8b 5c 24 18 43 8a 1c 0b 42 2a 1c 10 48 8b 44 24 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_EM_2147842498_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.EM!MTB"
        threat_id = "2147842498"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4d 6b d0 28 49 89 c3 4d 01 d3 49 83 c3 1c 4d 6b d0 28 48 89 c6 4c 01 d6 48 83 c6 20 4d 6b d0 28 4c 01 d0 89 cf 41 89 fa 4c 03 94 24 b8 00 00 00 45 00 c9 41 8b 3b 48 8b 16 33 38}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_RPY_2147843431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.RPY!MTB"
        threat_id = "2147843431"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 40 48 8b 4c 24 58 48 8b 54 24 18 44 8a 04 0a 25 ff 00 00 00 89 c0 89 c1 4c 8b 4c 24 10 45 32 04 09 48 8b 4c 24 58 4c 8b 54 24 28 45 88 04 0a 48 8b 4c 24 58 48 83 c1 01 4c 8b 5c 24 30 48 89 4c 24 50 8b 44 24 44 89 44 24 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DS_2147853135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DS!MTB"
        threat_id = "2147853135"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {be 7a 39 86 47 48 8b 0d [0-4] bf e2 2f cf c4 ba 41 6a 06 a2 41 b8 7a 39 86 47 48 89 4c 24 38 89 f9 4c 8b 4c 24 38 89 44 24 34 44 89 54 24 30 44 89 5c 24 2c 89 74 24 28 41 ff d1 4c 8b 4c 24 78 48 8b 5c 24 60 49 01 d9 49 81 f9 63 3e 00 00 89 44 24 24 4c 89 8c 24 80 00 00 00 0f 84}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8b 84 24 80 00 00 00 48 8b 0d [0-4] 48 89 44 24 78 ff d1 48 8d 0d [0-4] 48 8b 94 24 a0 00 00 00 48 81 f2 4f d6 a9 3a 4c 8d 05}  //weight: 2, accuracy: Low
        $x_1_3 = "TcLrNhYKFKdkmXtn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GME_2147888261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GME!MTB"
        threat_id = "2147888261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 8b 44 24 56 8a 4c 24 07 80 f1 ff 48 8b 54 24 58 88 4c 24 71 66 05 4a 92 48 81 f2 ?? ?? ?? ?? 4c 8b 44 24 28 49 01 d0 66 c7 44 24 72 93 41 4c 89 44 24 20 66 3b 44 24 46 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_MKV_2147900569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.MKV!MTB"
        threat_id = "2147900569"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af d2 48 89 8c 24 ?? ?? ?? ?? c1 e2 01 89 54 24 7c 8b 54 24 3c 33 94 24 88 00 00 00 89 94 24 ?? ?? ?? ?? 8b 54 24 3c 0f af d2 48 c7 84 24 ?? ?? ?? ?? 75 fd a1 ef 89 94 24 84 00 00 00 8b 54 24 5c 44 8b 44 24 3c 45 0f af c0 44 89 44 24 78 39 d0 0f 87}  //weight: 1, accuracy: Low
        $x_1_2 = {45 89 c8 44 89 c2 44 8b 84 24 ?? ?? ?? ?? 41 81 c0 30 88 7e 1f 44 89 84 24 88 00 00 00 8a 0c 10 88 8c 24 ?? ?? ?? ?? 44 8b 44 24 4c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_GXZ_2147904601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.GXZ!MTB"
        threat_id = "2147904601"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 89 f0 4d 0f af c0 4d 01 d9 4d 01 c1 8b 4d cc d3 e8 89 45 24 48 8b 4d a0 4c 8b 45 d0 49 d3 e8 4c 8b 55 18 4c 89 45 10 49 01 f2 81 f2 7c 71 00 00 4d 0f af d2 89 55 ec 8b 45 cc 2d ?? ?? ?? ?? 8b 55 04 89 45 24 89 55 0c 4d 39 d1 0f 85}  //weight: 10, accuracy: Low
        $x_1_2 = "@.uclgtf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ASFS_2147906242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ASFS!MTB"
        threat_id = "2147906242"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6d 6f 64 65 66 72 6f 6d 41 62 74 6f 74 73 65 72 2e 59 47 00 4b 35 6e 6c 6e 6f 74 00 6f 6e 75 70 6b 72 65 61 73 6f 6e 69 6e 67 43 68 72 74 6d 74 32 74 4c 5a 63 49 6e 74 65 72 6e 65 74 32 30 30 74 2e 32 38}  //weight: 2, accuracy: High
        $x_2_2 = {74 43 74 74 69 72 74 74 69 73 74 69 75 6e 69 74 72 69 6e 74 74 73 74 64 58 00 4e 74 69 74 74 69 74 39 74 43 69 72 6f 69 74 37 42 74 69 74 00 67 74 69 66 74 72 33 66 69 69 74 69 6c 4f 74 6f 74 69 65 69 73 00 74 74 59 36 56 70 65 74 76 74 64 75 73 65 00 74 74 65 79 66 42 53 6b 69 61 68 00 4e 43 6b 75 33 4f 69 6e 00 62 6a 61 6b 65 74 75 63 6b 65 72 4a 69 6e 66 72 6f 6d 7a 47}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ADR_2147924205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ADR!MTB"
        threat_id = "2147924205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 c0 48 8b 4c 24 40 48 81 c1 ?? ?? ?? ?? 89 44 24 4c 8a 54 24 03 80 f2 ff 4c 8b 44 24 28 88 54 24 37 8a 54 24 03 80 f2 d7 4c 8b 4c 24 20 47 8a 14 01 88 54 24 37 4c 8b 5c 24 10 47 88 14 03 66 8b 34 24 66 81 ce 07 0d 49 01 c8}  //weight: 2, accuracy: Low
        $x_1_2 = "Eofkiwerez4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_ADR_2147924205_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.ADR!MTB"
        threat_id = "2147924205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 29 d1 66 44 8b 44 24 ?? 66 45 21 c0 66 44 89 84 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 66 44 8b 44 24 ?? 66 41 83 f0 ff 66 44 89 84 24 ?? ?? ?? ?? 4c 8b 4c 24}  //weight: 1, accuracy: Low
        $x_2_2 = {44 29 c2 44 8b 4c 24 28 89 54 24 3c 44 8a 54 24 39 66 44 8b 5c 24 22 66 44 89 5c 24 3a 41 80 f2 28 c6 44 24 4f 18 8a 5c 24 39 48 8b 44 24 18 48 83 f0 ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_LZV_2147931184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.LZV!MTB"
        threat_id = "2147931184"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 14 01 4c 8b 44 24 08 41 88 14 00 8a 54 24 ?? 80 f2 ff 88 54 24 27 48 83 c0 01 4c 8b 4c 24 28 49 81 e9 8c f8 35 37 4c 89 4c 24 28 66 44 8b 54 24 ?? 66 44 23 54 24 36 66 44 89 54 24 ?? 4c 8b 4c 24 10 4c 39 c8 48 89 04 24 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_BVV_2147931266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.BVV!MTB"
        threat_id = "2147931266"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d6 48 8d 4d d0 48 8b d8 e8 ?? ?? ?? ?? 8b d6 48 8d 4d e8 40 8a 38 40 32 3b e8 ?? ?? ?? ?? ff c6 40 88 38 41 3b f7 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_PGD_2147939656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.PGD!MTB"
        threat_id = "2147939656"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 44 24 64 8b 44 24 34 35 07 18 8d 5a 89 84 24 a8 00 00 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dridex_DRX_2147951976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dridex.DRX!MTB"
        threat_id = "2147951976"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 d3 e2 48 89 55 e0 8a 4d d3 88 08 48 8b 45 88 48 69 d0 ?? ?? ?? ?? 48 89 55 e0 b8 77 a9 00 00 89 c1 48 2b 4d 00 8b 45 bc 8b 55 a4 83 f2 ff 89 55 b8 4c 8b 45 ?? 4c 31 c1 83 c0 01 48 89 4d e0 89 45 bc e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


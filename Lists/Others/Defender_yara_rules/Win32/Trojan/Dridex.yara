rule Trojan_Win32_Dridex_S_2147730473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.S!MTB"
        threat_id = "2147730473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c1 89 07 59 5a 4a 47 49 75 [0-96] ac 52 51 8b c8 8b 07 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AC_2147733242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AC!MTB"
        threat_id = "2147733242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FFPGGLBM.pdb" ascii //weight: 3
        $x_3_2 = "CreateAsyncBindCtxEx" ascii //weight: 3
        $x_3_3 = "RpcServerUseProtseqA" ascii //weight: 3
        $x_3_4 = "PathRemoveBlanksA" ascii //weight: 3
        $x_3_5 = "LookupIconIdFromDirectoryEx" ascii //weight: 3
        $x_3_6 = "ScrollConsoleScreenBufferA" ascii //weight: 3
        $x_3_7 = "SHEnumerateUnreadMailAccountsW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_A_2147740754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.A"
        threat_id = "2147740754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DEV\\SOFT\\DEBUG.pdb" ascii //weight: 1
        $x_1_2 = "FuckThePolice" ascii //weight: 1
        $x_1_3 = "BSecurity7VforXcycle" wide //weight: 1
        $x_1_4 = "QZpasswordFremarksmeaningkandk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Dridex_B_2147740756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.B"
        threat_id = "2147740756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 c4 b1 10 66 8b 55 d2 66 81 e2 ?? ?? 66 89 55 d2 8a 2c 05 ?? ?? ?? ?? 8b 75 cc 29 f6 89 75 d4 28 e9 02 0c 05 ?? ?? ?? ?? 88 4c 05 d8 83 c0 01 83 f8 0e 89 45 c4 75 c7}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 45 88 b1 39 8a 14 05 ?? ?? ?? ?? 66 c7 45 d4 88 65 28 d1 02 0c 05 ?? ?? ?? ?? 88 4c 05 dc 83 c0 01 83 f8 0e 89 45 88 74 cf eb d4}  //weight: 5, accuracy: Low
        $x_2_3 = {4c 43 cf 8a 5f 49 4c 43 cf 8a 5f 49 4c 43 cf 8a}  //weight: 2, accuracy: High
        $x_3_4 = "IpaE1TylJx.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_BK_2147741157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BK!MTB"
        threat_id = "2147741157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IKKIand80passphrase" ascii //weight: 1
        $x_1_2 = "qaensuresbyleastSeptemberp2competitors" ascii //weight: 1
        $x_1_3 = "29YbloggersPlayerwL" ascii //weight: 1
        $x_1_4 = "HBhcriticismXWDAcid2hversions" ascii //weight: 1
        $x_1_5 = "faster.Wanthonyj666666from" ascii //weight: 1
        $x_1_6 = "searchnewyorkwithinascNB4" wide //weight: 1
        $x_1_7 = "8OstabilitybarPresbyteriand" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PK_2147741158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PK!MTB"
        threat_id = "2147741158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "88usagePvulnerabilitieshtoQ9" wide //weight: 1
        $x_1_2 = "fromMalwarenow" wide //weight: 1
        $x_1_3 = "jacksonOgeneration,openeduser89.75%booby-trapped7" wide //weight: 1
        $x_1_4 = "spankyfaovercameaction" wide //weight: 1
        $x_1_5 = "SPDYGBakbRGoogleubailey" wide //weight: 1
        $x_1_6 = "ofshortenedQBYEngland" wide //weight: 1
        $x_1_7 = "arefiledbostoniXaddedto" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PK_2147741158_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PK!MTB"
        threat_id = "2147741158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 c1 83 64 [0-3] a2 [0-4] 6b [0-2] 89 [0-3] 2b d8 8a [0-3] 2a [0-5] 89 [0-5] 04 30 8b [0-6] 80 [0-2] 02 [0-3] 81 [0-5] 89 [0-5] a2 [0-4] 88 [0-5] 89 [0-5] 89 [0-6] 83 [0-2] 8b [0-5] 8d [0-2] 0f [0-2] 8b cd 89 [0-3] 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_TK_2147742137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.TK!MTB"
        threat_id = "2147742137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lipublishedkthefrom3Board" ascii //weight: 1
        $x_1_2 = "the8-bituMomzChrome" ascii //weight: 1
        $x_1_3 = "5troubleGoogleoftophasetherezentirely.101with" ascii //weight: 1
        $x_1_4 = "Ewhichwaslfor" ascii //weight: 1
        $x_1_5 = "crash3ChromeNversion" ascii //weight: 1
        $x_1_6 = "legendafterdirectlyk5lmonkey" ascii //weight: 1
        $x_1_7 = "0modeDthosethumbnailsy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DK_2147742138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DK!MTB"
        threat_id = "2147742138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EoreceivingftheITrinity" ascii //weight: 1
        $x_1_2 = "andofiscoffee1spiritN" ascii //weight: 1
        $x_1_3 = "BetaGcartmanPTheseMozillaIwhichpopular" ascii //weight: 1
        $x_1_4 = "includedfootballGooglethe8PFebruaryand65" ascii //weight: 1
        $x_1_5 = "0bytimeenginejanimalpwithAU" ascii //weight: 1
        $x_1_6 = "the7ServerwasisangelaMayM" ascii //weight: 1
        $x_1_7 = "SmaverickBtheirPwn2OwnusermastertheChromeW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DK_2147742138_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DK!MTB"
        threat_id = "2147742138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 5d fb 32 5d fb 88 5d fb 89 45 ec}  //weight: 10, accuracy: High
        $x_3_2 = "DoorrledFgppr" ascii //weight: 3
        $x_3_3 = "Gpernfedeefe.pdb" ascii //weight: 3
        $x_3_4 = "kernel32.Sleep" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DK_2147742138_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DK!MTB"
        threat_id = "2147742138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "llitPoRicy.189" ascii //weight: 3
        $x_3_2 = "ppgtmv.pdb" ascii //weight: 3
        $x_3_3 = "8thezbyforkedoto" ascii //weight: 3
        $x_3_4 = "MprAdminMIBBufferFree" ascii //weight: 3
        $x_3_5 = "ScrollConsoleScreenBufferA" ascii //weight: 3
        $x_3_6 = "SetupDiGetDeviceInstallParamsA" ascii //weight: 3
        $x_3_7 = "QueryUsersOnEncryptedFile" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NK_2147742547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NK!MTB"
        threat_id = "2147742547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "codeGztheNprivacyasChrome" wide //weight: 1
        $x_1_2 = "hentaiJcodecsofChromium,2015.188" wide //weight: 1
        $x_1_3 = "toRco-founderswithsEandfor" wide //weight: 1
        $x_1_4 = "revisions0000001Ioffery" wide //weight: 1
        $x_1_5 = "canZxnote5B9hLinuxsending" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NK_2147742547_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NK!MTB"
        threat_id = "2147742547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PrivacysprovideYSeptembertoqJanuaryV" wide //weight: 1
        $x_1_2 = "wAnnouncementxabilityandtoaStableD" wide //weight: 1
        $x_1_3 = "XQtheInternettoaconfinedlayoutitsEngland" ascii //weight: 1
        $x_1_4 = "launchedModee1Zpathologywhateverxrobertreflects" ascii //weight: 1
        $x_1_5 = "oincognito6fromQ" wide //weight: 1
        $x_1_6 = "betaatabletszr2theBranch" wide //weight: 1
        $x_1_7 = "23default,totakeChromersupermanRLChrome" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NK_2147742547_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NK!MTB"
        threat_id = "2147742547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 a1 ?? ?? ?? ?? 33 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b d1 01 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_CK_2147742920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.CK!MTB"
        threat_id = "2147742920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#thewalkerz4bothNou" ascii //weight: 1
        $x_1_2 = "Category:GooglecomputerJP" ascii //weight: 1
        $x_1_3 = "0rExplorer3jPZ29,aby" ascii //weight: 1
        $x_1_4 = "RhFirefox,3OnOGoogleLt" ascii //weight: 1
        $x_1_5 = "bloggersChromexOwasPN" ascii //weight: 1
        $x_1_6 = "Girenderingmed4availablexxrelease" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GK_2147743387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GK!MTB"
        threat_id = "2147743387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@ofkiwerez4" ascii //weight: 1
        $x_1_2 = "frequentoncodevf" ascii //weight: 1
        $x_1_3 = "WYovulnerabilities8S" ascii //weight: 1
        $x_1_4 = "Thisb12theaddressaccordingAlternatively,to" ascii //weight: 1
        $x_1_5 = "5KGoogle2s6jZCm" ascii //weight: 1
        $x_1_6 = "processes2wHtheBadger" ascii //weight: 1
        $x_1_7 = "GetTextExtentExPointI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_HK_2147743388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.HK!MTB"
        threat_id = "2147743388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 00 61 00 6c 00 6c 00 63 00 68 00 72 00 69 00 73 00 61 00 6c 00 6c 00 4e 00 6f 00 74 00 53 00 6f 00 6f 00 6e 00 72 00 6f 00 73 00 65 00 62 00 75 00 64 00 95 00}  //weight: 1, accuracy: High
        $x_1_2 = "CKIncognito0hprogrammeddetailsDNS9" wide //weight: 1
        $x_1_3 = "4.1usersdevisMUFirefoxandadV" wide //weight: 1
        $x_1_4 = "huChromerevealingagainstthemesT" wide //weight: 1
        $x_1_5 = "rEplacefkitten" wide //weight: 1
        $x_1_6 = "jonathanaECMAScripttQ" wide //weight: 1
        $x_1_7 = "a52009,passphrase.5wotherOcan" wide //weight: 1
        $x_1_8 = "yuseisVmajor.minorupbthe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Dridex_JK_2147743389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.JK!MTB"
        threat_id = "2147743389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StartingUjusageuxxdeemedFEverywhere" ascii //weight: 1
        $x_1_2 = "ChromeWebKit,Fu9gTheorwasvideo" ascii //weight: 1
        $x_1_3 = "Nt1eWhenThishsubmissionschrisfor" ascii //weight: 1
        $x_1_4 = "Omnibox.ChromeofNVin1924AreaN" ascii //weight: 1
        $x_1_5 = "ofIcommunitypopularRvisited" ascii //weight: 1
        $x_1_6 = "professorlastTforeignmajor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_A_2147743987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.A!MSR"
        threat_id = "2147743987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "nQTldIkcAJ7LIT.pdb" ascii //weight: 1
        $x_1_2 = {8b 5c 24 20 8a 24 0b 0f b6 d8 01 fb 81 e3 ?? ?? ?? ?? 8b 7c 24 ?? 32 24 1f 8b 5c 24 ?? 88 24 0b 83 c1 ?? 8b 7c ?? ?? 39 f9 89 4c 24 ?? 89 54 24 ?? 89 74 24 ?? 0f 84 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_2_3 = {88 3c 31 88 1c 11 0f b6 0c 31 01 f9 81 e1 ff 00 00 00 8b 7c 24 14 8a 1c 0f 8b 4c 24 1c 8b 74 24 04 32 1c 31 8b 4c 24 18 88 1c 31 83 c6 01 8b 4c 24 20 39 ce 8b 0c 24 89 4c 24 08 89 54 24 0c 89 74 24 10 74 1c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_B_2147744647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.B!MSR"
        threat_id = "2147744647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\Top\\Train\\job\\Wall\\Did\\Spendkept.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_G_2147744820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.G!MTB"
        threat_id = "2147744820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e8 01 74 ?? 8d 86 ?? ?? ?? ?? 0f b7 c0 2a c7 0f b7 f2 2c 4a 8a f8 8b 01 05 dc f2 0c 01 89 01 83 c1 04 83 6c 24 ?? 01 a3 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_TB_2147744946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.TB!MSR"
        threat_id = "2147744946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "robertmajor.minorDointeractivitytoVbeJ" wide //weight: 1
        $x_1_2 = "tothisBasedNPAPIvy" ascii //weight: 1
        $x_1_3 = "TheJGweeksEuropeanowebsitegarbage" ascii //weight: 1
        $x_1_4 = "Gvoandin2018,YboxjackieY" wide //weight: 1
        $x_1_5 = "BrinGooglei" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_R_2147745155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.R!MSR"
        threat_id = "2147745155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "F:\\ewhjR#HREjrejERjer\\wjREjwRJRJ\\Text.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_D_2147745215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.D!MSR"
        threat_id = "2147745215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "JwEEPNd--41U6@yY_2Y.WDH6GG*6RbR.pdb" ascii //weight: 4
        $x_1_2 = "tricksthisandtoufailed;lineX" wide //weight: 1
        $x_1_3 = "d8perthree.Trinityenabledastaking" wide //weight: 1
        $x_1_4 = "5OOmniboxthepneedsoreputationbyF" ascii //weight: 1
        $x_1_5 = "bigtitsstarwarskchannelGfor2010.158y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_AA_2147746080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AA!MTB"
        threat_id = "2147746080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 c2 8a f2 66 3b c6 74 24 0f b7 01 0f af d8 8a d3 2a 54 24 10 80 ea 35 0f b6 c2 8a f2 66 3b c7 74 0b}  //weight: 10, accuracy: High
        $x_10_2 = {0f b6 c1 66 3b c7 74 26 0f b7 02 0f af d8 8a cb 2a 4c 24 10 80 e9 35 0f b6 c1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AA_2147746080_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AA!MTB"
        threat_id = "2147746080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 16 03 f8 0f b7 c1 03 d8 89 1d ?? ?? ?? ?? 0f b7 1d ?? ?? ?? ?? 2b eb 81 fd 6a 02 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 4c 28 01 81 c2 cc bc 05 01 0f b7 c9 89 16 89 15 ?? ?? ?? ?? 0f b7 d1 8d 84 00 e8 3b 00 00 2b c2 03 c7 83 c6 04 83 6c 24 10 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AA_2147746080_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AA!MTB"
        threat_id = "2147746080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 8a 24 0a 34 ff 00 c4 88 24 0e 5e 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d e8 8b 55 ec 8a 5d e7 32 5d de 29 d0 8b 55 b4 88 1c 0a 8b 4d d8 03 45 e8 89 4d c8 89 45 c4 8b 4d c0 89 4d d0 8b 4d bc 39 c8 0f 84 ?? ?? 00 00 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SA_2147746099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SA!MTB"
        threat_id = "2147746099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 03 31 [0-32] 8a 2c 3b [0-10] 30 cd [0-16] 88 2c 07 83 c0 01 [0-6] 39 f8 [0-21] 0f [0-6] e9}  //weight: 1, accuracy: Low
        $x_1_2 = "somewhattypedrOmode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GA_2147748074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GA!MTB"
        threat_id = "2147748074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 cb 66 3b cf 74 ?? 0f b7 10 0f af d6 8a ca 8b f2 2a cb 89 35 ?? ?? ?? ?? 2a 4c 24 ?? 8a d9 0f b7 cd 3b d1 74 ?? 83 c0 02 3d ?? ?? ?? ?? 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GA_2147748074_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GA!MTB"
        threat_id = "2147748074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f6 5b fe c5 47 39 f0 89 45 ?? 89 4d ?? 89 55 [0-48] 8b 45 ?? 8b 4d ?? 8a 55 ?? 88 14 01 83 c0 ?? 8b 75 ?? 39 f0 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GA_2147748074_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GA!MTB"
        threat_id = "2147748074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "S:\\Work\\_bin\\Release-Win32\\ldr.pdb" ascii //weight: 10
        $x_1_2 = "OutputDebugStringA" ascii //weight: 1
        $x_1_3 = "DebugBreak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GA_2147748074_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GA!MTB"
        threat_id = "2147748074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 23 00 cc cc [0-1] cc}  //weight: 10, accuracy: Low
        $x_5_2 = {29 df 89 fb 88 dc 88 64 24 ?? 8b 7d ?? 8b 5d ?? 8a 64 24 ?? 88 24 3b 66 8b 7c 24 ?? 66 89 7c 24 ?? 88 44 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_GA_2147748074_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GA!MTB"
        threat_id = "2147748074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 23 00 cc cc cc eb}  //weight: 10, accuracy: Low
        $x_10_2 = "MYAPP.EXE" wide //weight: 10
        $x_10_3 = "self.exe" wide //weight: 10
        $x_10_4 = "WneedswhichGhosteryxAD" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Dridex_GA_2147748074_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GA!MTB"
        threat_id = "2147748074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ea 01 2b 55 ?? 89 15 ?? ?? ?? ?? 0f b7 45 ?? 0f af 05 ?? ?? ?? ?? 2b 45 ?? 66 89 45 ?? 0f b7 4d ?? 0f af 0d ?? ?? ?? ?? 2b 4d ?? 66 89 4d ?? 0f b7 55 ?? 8b 45 ?? 8d 8c 10 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 75 ?? 81 c2 ?? ?? ?? ?? 83 c6 03 83 ee 03 81 c2 ?? ?? ?? ?? ff e6}  //weight: 10, accuracy: Low
        $x_10_2 = {64 a1 00 00 00 00 50 83 c4 f0 53 56 57 a1 ?? ?? ?? ?? 31 45 ?? 33 c5 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GA_2147748074_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GA!MTB"
        threat_id = "2147748074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 fa 81 f2 ?? ?? ?? ?? 89 54 24 ?? 89 5c 24 ?? 0f b6 04 08 89 c1 0f b6 55 ?? 29 d0 88 c5 89 5c 24 ?? 89 7c 24 ?? 88 6c 24 ?? 8b 45 ?? 8b 55 ?? 8a 6c 24 ?? 80 f1 ff 88 4c 24 ?? 88 2c 10 89 74 24 ?? 8d 65}  //weight: 10, accuracy: Low
        $x_10_2 = {cc cc 40 cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3}  //weight: 10, accuracy: Low
        $x_10_3 = "tttt32" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GA_2147748074_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GA!MTB"
        threat_id = "2147748074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "resultsstatementkillerfeaturesThe" ascii //weight: 1
        $x_1_2 = "2015assholetyped" ascii //weight: 1
        $x_1_3 = "batmanI8files)QzFor" ascii //weight: 1
        $x_1_4 = "L2008,randoluckyY" ascii //weight: 1
        $x_1_5 = "threeAmeaningLinuxey" ascii //weight: 1
        $x_1_6 = "MZbutxmtaitk" ascii //weight: 1
        $x_1_7 = "speedyvcricketfailed.International" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Dridex_DSK_2147748122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DSK!MTB"
        threat_id = "2147748122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4c 24 34 8b 54 24 5c 8b 74 24 14 01 d6 89 74 24 2c 8b 54 24 2c 8a 1a 88 5c 24 47 35 1d ce 0a 60 09 c8}  //weight: 2, accuracy: High
        $x_2_2 = {8a 44 05 f4 30 86 ?? ?? ?? ?? 8b c7 83 e0 03 83 c7 06 8a 44 05 f4 30 86 ?? ?? ?? ?? 83 c6 06 81 fe e2 02 00 00 72}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 44 24 48 8b 4c 24 4c 66 8b 54 24 46 66 f7 d2 35 77 ae 61 00 8b 74 24 50 8b 7c 24 54 01 f6 11 ff 09 c8 66 89 54 24 46}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_SB_2147749822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SB!MSR"
        threat_id = "2147749822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jordan" ascii //weight: 1
        $x_1_2 = "bullshit" ascii //weight: 1
        $x_1_3 = "asshole" ascii //weight: 1
        $x_1_4 = "cowboy" ascii //weight: 1
        $x_1_5 = "faulted" ascii //weight: 1
        $x_1_6 = "Twitter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SC_2147749840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SC!MSR"
        threat_id = "2147749840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bookmarks" wide //weight: 1
        $x_1_2 = "browser" wide //weight: 1
        $x_1_3 = "chrome" wide //weight: 1
        $x_1_4 = "Firefox" ascii //weight: 1
        $x_1_5 = "bacteriologyversion" ascii //weight: 1
        $x_1_6 = "godzilla" ascii //weight: 1
        $x_1_7 = "pussy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_A_2147750565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.A!MTB"
        threat_id = "2147750565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 54 24 6b 8b 5c 24 38 8b 54 24 1c 8a 04 1a 8b 54 24 50 69 d2 [0-4] 01 f1 21 f9 89 54 24 50 8b 54 24 14 8a 24 0a 30 c4 31 c9 89 4c 24 5c c7 44 24 58 6b 0a f2 61 8b 74 24 18 88 24 1e 8b 7c 24 58 81 e7 bf 89 6f 54 8b 5c 24 38 43}  //weight: 1, accuracy: Low
        $x_1_2 = {88 5c 24 77 8b 54 24 44 66 c7 44 24 66 0a fb 8b 74 24 44 8b 7c 24 2c 8a 1c 17 8b 54 24 24 32 1c 02 8b 44 24 28 88 1c 30 8b 74 24 48 8b 44 24 44 83 c0 01 8a 5c 24 23 80 cb ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_DX_2147750650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DX!MTB"
        threat_id = "2147750650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 24 3e 66 c7 44 24 ?? ?? ?? 30 e0 b4 ?? 8a 54 24 ?? 88 44 24 ?? 88 d0 f6 e4 88 44 24 ?? 8b 5c 24 ?? 8a 44 24 ?? 88 04 3b 83 c7 ?? 8b 44 24 ?? 39 c7 8b 44 24 ?? 89 44 24 ?? 89 4c 24 ?? 89 7c 24 ?? 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_B_2147750747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.B!MTB"
        threat_id = "2147750747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fe 8b 4d e0 8a 3c 11 8b 75 c8 88 3c 31 88 1c 11 8b 4d f0 81 c1 [0-4] 8b 75 e0 8b 5d c8 0f b6 34 1e 01 fe 81 e6 [0-4] 8b 7d e8 8b 5d cc 8a 1c 1f 8b 7d e0 32 1c 37 8b 75 e4 8b 7d cc 88 1c 3e 01 cf 8b 4d ec 39 cf}  //weight: 1, accuracy: Low
        $x_1_2 = {99 f7 f9 8b 4d b8 2b 4d f0 8b 7d e4 8b 5d bc 8a 1c 13 88 1f 8a 5d ef 8b 7d bc 88 1c 17 8b 7d e4 0f b6 3f 01 f7 21 cf 8b 4d bc 8a 1c 39 8b 75 d8 8b 7d c4 32 1c 37 8b 75 d8 8b 4d c0 88 1c 31 8b 75 d8 83 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_C_2147750751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.C!MTB"
        threat_id = "2147750751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c6 8b 44 24 20 8a 3c 30 88 3c 10 88 1c 30 c7 44 24 3c [0-4] c7 44 24 38 [0-4] 8b 4c 24 08 8a 1c 08 66 8b 44 24 1e 66 0f af c0 0f b6 d3 66 89 44 24 36 01 fa 81 e2 [0-4] 8b 7c 24 20 8a 1c 17 8b 54 24 28 8b 0c 24 32 1c 0a 8b 4c 24 24 8b 14 24 88 1c 11 83 c2 01 8b 4c 24 2c 39 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PA_2147750752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PA!MTB"
        threat_id = "2147750752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ESTAPPPexe" ascii //weight: 1
        $x_1_2 = "QDdefaults" ascii //weight: 1
        $x_1_3 = "numberthem" ascii //weight: 1
        $x_1_4 = "FGERN.pdb" ascii //weight: 1
        $x_1_5 = "Oracle Corporation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PA_2147750752_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PA!MTB"
        threat_id = "2147750752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Gsp.pdb" ascii //weight: 1
        $x_1_2 = "QfreeFyckhIG" wide //weight: 1
        $x_2_3 = "gpmgpmgpm.dll" wide //weight: 2
        $x_3_4 = {8b 44 24 10 8a 8c 24 ?? ?? ?? ?? 80 f1 46 8a [0-6] 8b b4 24 ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 88 8c 24 ?? ?? ?? ?? 8b bc 24 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 89 bc 24 ?? ?? ?? ?? 8a 88 ?? ?? ?? ?? 8b 7c 24 ?? 89 bc 24 ?? ?? ?? ?? 8b 5c 24 ?? 89 9c 24 ?? ?? ?? ?? 28 d1 88 4c 04 ?? 83 c0 01 39 f0 89 44 24 ?? 75}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PA_2147750752_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PA!MTB"
        threat_id = "2147750752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 57 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 89 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 8b 02 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 81 e9 fc 1a 01 00 89 0d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 81 c1 fc 1a 01 00 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 b8 13 00 01 00 00 03 a1 ?? ?? ?? 00 31 0d ?? ?? ?? 00 [0-240] 8b ff c7 05 ?? ?? ?? 00 00 00 00 00 a1 ?? ?? ?? 00 01 05 ?? ?? ?? 00 8b ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 89 02 5f 5d c3}  //weight: 10, accuracy: Low
        $x_1_2 = {8d 84 02 92 27 01 00 8b 4d 08 03 01 8b 55 08 89 02 8b 45 08 8b 08 81 e9 92 27 01 00 8b 55 08 89 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BS_2147751667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BS!MTB"
        threat_id = "2147751667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e9 2d ad 00 00 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_2 = {68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 45 ?? 8b 55 ?? 8a 0c 32 88 0c 38 8b 55 ?? 83 c2 01 89 55 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BS_2147751667_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BS!MTB"
        threat_id = "2147751667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8b 7d ?? 03 7d ?? 68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 45 ?? 8b 55 ?? 8a 0c 32 88 0c 38 8b 55 ?? 83 c2 01 89 55 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e9 2d ad 00 00 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SD_2147752152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SD!MSR"
        threat_id = "2147752152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powerdear\\dangerRain\\sinceSugar\\Centersubtract\\PathWell\\MaterialName\\alltallhis.pdb" ascii //weight: 1
        $x_1_2 = "LockWindowUpdate" ascii //weight: 1
        $x_1_3 = "LockFile" ascii //weight: 1
        $x_1_4 = "LockResource" ascii //weight: 1
        $x_1_5 = "Pass Bellevery" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BA_2147752401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BA!MTB"
        threat_id = "2147752401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 ca 89 4c 24 1c 2b c8 83 c1 25 89 4c 24 18 83 fe 09 74 1e 0f b6 c8 8a d3 6b c9 1a f6 da 2a d1 8b 4c 24 10 02 ca 89 4c 24 10}  //weight: 10, accuracy: High
        $x_10_2 = {29 19 8d 50 29 83 e9 08 89 54 24 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BA_2147752401_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BA!MTB"
        threat_id = "2147752401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ea 2d ad 00 00 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ba 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BA_2147752401_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BA!MTB"
        threat_id = "2147752401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 8b 55 d8 01 02 8b 45 c8 03 45 a8 2d 67 2b 00 00 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4}  //weight: 1, accuracy: High
        $x_1_2 = "tgkgethjrngewub4yh2221ujmetrfv1et734tdcw16sxqa1z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BZ_2147753300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BZ!MTB"
        threat_id = "2147753300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e9 2d ad 00 00 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? b9 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AR_2147754239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex!MTB.AR!MTB"
        threat_id = "2147754239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 96 89 5c 24 10 66 89 1d ?? ?? ?? ?? 8d 1c 4d 74 7b fe ff 89 1d ?? ?? ?? ?? 8b 4c 24 0c 81 c7 30 50 07 01 8b f2 89 3d ?? ?? ?? ?? 2b f0 83 c6 33 89 39 8b 4c 24 10 0f b7 c9 83 e9 01 74}  //weight: 1, accuracy: Low
        $x_1_2 = {00 c4 8b 54 24 10 8a 04 0a 04 cf 28 e0 8b 74 24 0c 88 04 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_RAA_2147754381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RAA!MTB"
        threat_id = "2147754381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ba b4 12 00 00 ba bc 01 00 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? eb}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RAA_2147754381_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RAA!MTB"
        threat_id = "2147754381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 2b 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEA_2147754465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEA!MTB"
        threat_id = "2147754465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 13 00 01 00 b8 13 00 01 00 b8 13 00 01 00 b8 13 00 01 00 b8 13 00 01 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEB_2147754472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEB!MTB"
        threat_id = "2147754472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 2b c1 8b d5 2b d6 8d 54 13 ff 8b 1d ?? ?? ?? ?? 83 c0 50 03 d8 89 15 ?? ?? ?? ?? 8b 17 8d b4 0e ?? ?? ?? ?? 8d 8c 19 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 8b c1 2b c5 89 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEC_2147754560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEC!MTB"
        threat_id = "2147754560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 2b d1 03 ea 8b 54 24 ?? 83 44 24 ?? ?? 05 ?? ?? ?? ?? 89 02 a3 ?? ?? ?? ?? 0f b7 c5 6b c0 2d ba 4c 00 00 00 2b d0 2b d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DED_2147754605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DED!MTB"
        threat_id = "2147754605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b d0 59 8b 44 24 ?? 2b fe 05 ?? ?? ?? ?? 89 44 24 ?? a3 ?? ?? ?? ?? 8d 8f ?? ?? ?? ?? bf ?? ?? ?? ?? 03 ca 81 7c 24 ?? ?? ?? ?? ?? 8b 54 24 ?? 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEE_2147754612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEE!MTB"
        threat_id = "2147754612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d dc 8b 55 f0 8a 5d db 8b 75 e4 32 1e 29 d0 8b 55 c0 88 1c 0a 8b 4d dc 8b 75 d4 01 c1}  //weight: 1, accuracy: High
        $x_1_2 = {01 f9 81 e1 ff 00 00 00 8b 7d e8 8b 5d d0 8a 1c 1f 8b 7d e0 32 1c 0f 8b 4d e4 8b 7d d0 88 1c 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_DEF_2147754745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEF!MTB"
        threat_id = "2147754745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b da b9 fb ff ff ff 2b de 83 eb 05 66 89 1d ?? ?? ?? ?? 8b 44 24 10 8b 74 24 14 05 ?? ?? ?? ?? 89 44 24 10 a3 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 89 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEG_2147754746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEG!MTB"
        threat_id = "2147754746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 10 05 ?? ?? ?? ?? 89 07 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 8b fe 6b ff 4a}  //weight: 1, accuracy: Low
        $x_1_2 = {2b f3 83 e8 1b 8b 15 ?? ?? ?? ?? 8b 5c 24 10 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 13 8b d0 2b d1 81 ea ?? ?? ?? ?? 0f b7 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_RAB_2147754778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RAB!MTB"
        threat_id = "2147754778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2b 45 ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 4d ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_DEH_2147754796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEH!MTB"
        threat_id = "2147754796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 fb 81 c2 ?? ?? ?? ?? 03 f1 03 da 0f b7 c6 8b 54 24 10 8b 35 ?? ?? ?? ?? c1 e6 06 2b 35 ?? ?? ?? ?? 8b 12 89 54 24 0c 8b d0 03 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 03 f0 a3 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 8d 5c 33 ad 8a ca 8a c3 f6 e9 8a c8 a1 ?? ?? ?? ?? 02 0d ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 45 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_DEI_2147754798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEI!MTB"
        threat_id = "2147754798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f1 2b f7 83 ee 0f 6b c6 24 2b c7 03 c8 8d 7a 2c 03 fe 8b 54 24 10 8b 44 24 18 05 ?? ?? ?? ?? 89 44 24 18 89 02}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 0c 8d 4e 5f 8b 74 24 18 05 ?? ?? ?? ?? 83 44 24 18 04 03 ca a3 ?? ?? ?? ?? 89 06 6b f1 46 8b c6 2b c1 2b c7}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c8 2b cb 83 c1 3f 8b 54 24 18 b8 2c 00 00 00 2b c1 f7 d9 2b c3 03 f0 8b 44 24 10 05 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4c 24 0c 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 11 8b c8 c1 e1 05 8b d6 2b c8 03 c9 2b d1 8b 0d ?? ?? ?? ?? 2b d3}  //weight: 1, accuracy: Low
        $x_1_5 = {2b c8 83 c1 1f 89 0d ?? ?? ?? ?? 8b 44 24 2c 8b 54 24 0c 81 c2 ?? ?? ?? ?? 89 54 24 0c 89 10 8b 44 24 30 03 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_DEJ_2147754929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEJ!MTB"
        threat_id = "2147754929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 cf c1 e2 ?? f7 d9 2b ca 8b d0 2b 15 ?? ?? ?? ?? 01 0d ?? ?? ?? ?? 83 c2 ?? 89 15 ?? ?? ?? ?? 8b 4c 24 ?? 03 c6 03 f8 8b 44 24 ?? 05 ?? ?? ?? ?? 89 44 24 ?? 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEK_2147754969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEK!MTB"
        threat_id = "2147754969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ce 03 d1 89 15 ?? ?? ?? ?? 8b 74 24 0c 8b 4c 24 10 81 c1 ?? ?? ?? ?? 89 4c 24 10 89 0e be ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 4c 24 14 2b f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEL_2147754976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEL!MTB"
        threat_id = "2147754976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 2b f7 83 ee ?? 8b fe 8d 04 47 8d b4 10 ?? ?? ?? ?? eb 0e 8b c7 2b c2 48 a3 ?? ?? ?? ?? 8d 74 3f af 8b 6c 24 10 81 c3 ?? ?? ?? ?? 8d 84 0a ?? ?? ?? ?? 89 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEM_2147754977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEM!MTB"
        threat_id = "2147754977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 66 03 d1 8b 4c 24 ?? 0f b7 c2 66 89 15 ?? ?? ?? ?? 99 2b c8 0f b7 c6 1b fa 83 c1 ?? 99 83 d7 ?? 3b c8 a1 [0-15] 03 c3 03 c5 66 a3 ?? ?? ?? ?? 8b 44 24 ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEN_2147755072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEN!MTB"
        threat_id = "2147755072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 83 ef 5a 89 15 ?? ?? ?? ?? 8b 54 24 10 2b ce 8b 44 24 0c 03 cf 05 ?? ?? ?? ?? 89 44 24 0c 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEO_2147755293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEO!MTB"
        threat_id = "2147755293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cd 8b 7c 24 10 8b 44 24 18 83 44 24 10 04 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 07 6b fa 1e 03 fd 83 6c 24 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEP_2147755357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEP!MTB"
        threat_id = "2147755357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 10 2b c6 8b 0d ?? ?? ?? ?? 83 44 24 10 04 81 c1 ?? ?? ?? ?? 89 44 24 14 03 c1 8b 0f a3 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 2b c2 89 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEQ_2147755359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEQ!MTB"
        threat_id = "2147755359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d8 0f b7 d0 03 54 24 14 8b 0e 81 c1 ?? ?? ?? ?? 0f b7 c2 89 0e 05 ?? ?? ?? ?? 83 c6 04 83 6c 24 10 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b de 2b 5c 24 20 83 c3 05 8b 54 24 0c 8b c8 2b 4c 24 18 81 c2 ?? ?? ?? ?? 03 ce 89 54 24 0c 0f b7 c9 83 c6 27 81 7c 24 14 ?? ?? ?? ?? 89 4c 24 18 8b 4c 24 10 89 15 ?? ?? ?? ?? 89 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_DER_2147755436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DER!MTB"
        threat_id = "2147755436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c6 8d 04 83 89 44 24 1c 66 a3 ?? ?? ?? ?? 8b 7c 24 18 8b 44 24 10 05 ?? ?? ?? ?? 89 44 24 10 89 07 6b fb 1d a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 83 c7 09 03 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DES_2147755454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DES!MTB"
        threat_id = "2147755454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 83 ea 51 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d f8 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ?? ?? 8b 45 fc 03 05 ?? ?? ?? ?? 03 45 fc a3 ?? ?? ?? ?? b9 01 00 00 00 6b d1 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DET_2147755595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DET!MTB"
        threat_id = "2147755595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b ca 1b 03 cb 8b 44 24 10 2b d7 83 c2 b1 05 ?? ?? ?? ?? 03 ca 89 44 24 10 8b 54 24 18 a3 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RAC_2147755624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RAC!MTB"
        threat_id = "2147755624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 54 01 ?? 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 03 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? b8 87 8a 00 00 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 54 01 ?? 2b 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 15 a3 ?? ?? ?? ?? eb ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? b8 01 00 00 00 85 c0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_RAD_2147755664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RAD!MTB"
        threat_id = "2147755664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5f 33 00 00 85 c0 74 ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? eb ?? 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? 8a 00 88 04 11 8b 4d ?? 83 c1 01 89 4d ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DEU_2147755952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DEU!MTB"
        threat_id = "2147755952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 2b da 8b 15 ?? ?? ?? ?? 8d 54 13 02 8b 6c 24 10 8b d8 2b d9 03 fb 8b 1d ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 89 1d 01 89 5d 00 8b 1d 00 2b 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RA_2147756684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RA!MTB"
        threat_id = "2147756684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d e8 8b 75 dc 0f b6 34 33 01 fe 8b 7d ec 0f b6 14 17 01 d6 89 35 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 4c 23 00 00 89 f0 99 f7 f9 89 15 ?? ?? ?? ?? 8b 4d dc 8a 0c 0b 88 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GM_2147758069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GM!MTB"
        threat_id = "2147758069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 8b 4d ec 8a 14 01 8b 75 ?? 81 f6 78 29 34 0a 8b 7d ?? 88 14 07 01 f0 8b 75 ?? 39 f0 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GM_2147758069_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GM!MTB"
        threat_id = "2147758069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b6 73 28 ce c6 06 56 [0-40] 72 8a 5c 24 ?? 88 9c 24 ?? ?? ?? ?? c6 44 24 ?? 74 b7 9e 28 cf c6 44 24 ?? 75 88 6c 24 ?? c6 44 24 ?? 6c c6 84 24 ?? ?? ?? ?? 4a 88 74 24 73 88 cd 80 f5 5e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AG_2147758229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AG!MTB"
        threat_id = "2147758229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 83 c1 63 89 b4 3b a4 e8 ff ff 83 c7 04 8b 1d ?? ?? ?? ?? 66 03 cb 0f b7 d1 89 54 24 10 81 ff 74 18 00 00 73 1e}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 c8 8b 44 24 10 0f b7 d5 2b ca 0f b7 c0 83 c1 63 2b c2 03 ce 83 c0 63 03 c1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AG_2147758229_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AG!MTB"
        threat_id = "2147758229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Fomeoode" ascii //weight: 3
        $x_3_2 = "DmlooirmFert" ascii //weight: 3
        $x_3_3 = "kernel32.Sleep" ascii //weight: 3
        $x_3_4 = "RTTYEBHUY.pdb" ascii //weight: 3
        $x_3_5 = "StrCatBuffW" ascii //weight: 3
        $x_3_6 = "MprConfigServerConnect" ascii //weight: 3
        $x_3_7 = "AcquireCredentialsHandleW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AG_2147758229_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AG!MTB"
        threat_id = "2147758229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FFRgpmdlwwWde" ascii //weight: 3
        $x_3_2 = "RTTYEBHUY.pdb" ascii //weight: 3
        $x_3_3 = "ShowOwnedPopups" ascii //weight: 3
        $x_3_4 = "RegOverridePredefKey" ascii //weight: 3
        $x_3_5 = "SetupDiEnumDeviceInfo" ascii //weight: 3
        $x_3_6 = "hhooewdaqsx" ascii //weight: 3
        $x_3_7 = "kernel32.Sleep" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AG_2147758229_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AG!MTB"
        threat_id = "2147758229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "RTTYEBHUY.pdb" ascii //weight: 3
        $x_3_2 = "WriteGlobalPwrPolicy" ascii //weight: 3
        $x_3_3 = "FGtkemvb" ascii //weight: 3
        $x_3_4 = "submissionsIohclasswithinsandranewU" ascii //weight: 3
        $x_3_5 = "A42.0.2311.90dworGosUpdate," ascii //weight: 3
        $x_3_6 = "rrpoouenmvrw" ascii //weight: 3
        $x_3_7 = "forekiicndesxw" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AR_2147758618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AR!MTB"
        threat_id = "2147758618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 2c 8b 7c 24 28 81 c7 bb ef 21 47 83 d1 00 89 7c 24 28 89 4c 24 2c 3c 00 89 54 24 0c 88 44 24 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AR_2147758618_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AR!MTB"
        threat_id = "2147758618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 1c 05 fc 55 0e 01 89 02 8b 15 ?? ?? ?? ?? 89 44 24 1c a3 ?? ?? ?? ?? 8b c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AR_2147758618_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AR!MTB"
        threat_id = "2147758618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 60 01 01 00 ba 9c ad 00 00 a1 ?? ?? ?? ?? a3 [0-12] 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AR_2147758618_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AR!MTB"
        threat_id = "2147758618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 08 8b 4d fc 03 0d ?? ?? ?? ?? 8b 55 f4 03 15 ?? ?? ?? ?? 8a 02 88 01 33 c9 0f 84 ?? ?? ?? ?? 6a 04 6a 04}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d 87 10 00 00 8b 4d 08 89 01 5e 8b e5 5d c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AR_2147758618_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AR!MTB"
        threat_id = "2147758618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c2 00 73 02 00 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 5d 32 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 8c 10 9e 9a 56 00 2b 4d b0 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea 9e 9a 56 00 89 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AR_2147758618_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AR!MTB"
        threat_id = "2147758618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b ca 88 4d d7 b8 02 00 00 00 6b c8 09 0f b7 91 ?? ?? ?? ?? b8 02 00 00 00 6b c8 06 0f b7 81}  //weight: 10, accuracy: Low
        $x_3_2 = "Solution_one\\use.pdb" ascii //weight: 3
        $x_3_3 = "Completebegan" ascii //weight: 3
        $x_3_4 = "Searchneighbor" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_VAM_2147759264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.VAM!MSR"
        threat_id = "2147759264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 34 01 28 d6 80 c6 20 8b 74 24 14 88 34 06 83 c0 20 8b 7c 24 1c 39 f8 89 44 24 08 72 c7}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c 24 14 8a 14 01 80 c2 e0 88 14 01 83 c0 01 8b 74 24 1c 39 f0 89 04 24 74 b9 eb e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_MK_2147759723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.MK!MTB"
        threat_id = "2147759723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 12 35 09 00 77 07 cc cc cc 40 cc eb f2}  //weight: 10, accuracy: High
        $x_10_2 = {77 07 cc cc cc 40 cc eb f2 05 00 3d ?? ?? ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_MK_2147759723_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.MK!MTB"
        threat_id = "2147759723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 16 8d 7c 07 be 8d 0c 3f 8b c1 2b c6 0f af c5 69 c0 ?? ?? ?? ?? 4b 2b c8 8d bc 31 ?? ?? ?? ?? 85 db 75 d5}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0d 9c cc 44 00 0f b7 05 ?? ?? ?? ?? 6b c9 ?? 03 c8 8d 14 09 b8 ?? ?? ?? ?? 2b c2 0f b7 c0 89 0d ?? ?? ?? ?? 8d 4c 08 bf 89 0d ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_MK_2147759723_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.MK!MTB"
        threat_id = "2147759723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 eb 01 03 f3 8d 7c 37 ec 8d 77 e7 8b c6 6b c0 ?? 2b c5 01 05 ?? ?? ?? ?? 85 db 75 e3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 cb 8d 5c 02 ?? 8b c2 6b c0 ?? 8d 6c 29 c9 8b 0e 81 c1 ?? ?? ?? ?? 89 0e 2b c5 83 c6 ?? 83 6c 24 10 ?? 89 2d ?? ?? ?? ?? 8d 44 38 da 75 99}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RX_2147759726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RX!MTB"
        threat_id = "2147759726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c7 30 50 07 01 [0-5] 89 3d ?? ?? ?? ?? [0-10] 89 39 [0-47] 74}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c2 14 c8 08 01 89 16 83 c6 04 83 6c 24 10 01 66 89 0d [0-31] 75 3f 00 8d 4c 01 bf [0-15] 69 c9 ?? ?? ?? ?? 0f af d7 69 d2 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_GC_2147761787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GC!MTB"
        threat_id = "2147761787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 8b 75 ?? 88 14 06 83 c0 ?? 89 45 ?? 66 c7 45 [0-32] 66 81 7d [0-32] 8b 45 ?? 8b 4d ?? 89 4d ?? 8b 4d ?? 39 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GC_2147761787_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GC!MTB"
        threat_id = "2147761787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 4b 00 cc [0-10] cc [0-10] cc}  //weight: 10, accuracy: Low
        $x_2_2 = "llosewwq.ll" ascii //weight: 2
        $x_2_3 = ".pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_GC_2147761787_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GC!MTB"
        threat_id = "2147761787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 08 0e 00 00 00 [0-8] 89 4c 24 [0-10] e8}  //weight: 1, accuracy: Low
        $x_10_2 = {cc cc 40 cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3}  //weight: 10, accuracy: Low
        $x_10_3 = "tttt32" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GC_2147761787_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GC!MTB"
        threat_id = "2147761787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 64 a3 00 00 00 00 [0-40] 83 ec 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 53 00 cc [0-12] cc [0-12] cc}  //weight: 10, accuracy: Low
        $x_2_2 = "FGtkemvb" ascii //weight: 2
        $x_2_3 = "RTTYEBHUY.pdb" ascii //weight: 2
        $x_2_4 = "LdrGetProcedureA" ascii //weight: 2
        $x_2_5 = "ffty.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_GC_2147761787_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GC!MTB"
        threat_id = "2147761787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {69 88 b4 24 ?? ?? ?? ?? c6 84 24 ?? ?? ?? ?? 74 c6 84 24 ?? ?? ?? ?? 75 c6 84 24 ?? ?? ?? ?? 61 c6 84 24 ?? ?? ?? ?? 6c 8b 84 24 ?? ?? ?? ?? 35 ?? ?? ?? ?? c6 84 24 ?? ?? ?? ?? 41}  //weight: 10, accuracy: Low
        $x_10_2 = {4c 00 64 00 72 00 47 00 65 00 74 00 50 00 72 00 6f 00 63 00 65 00 64 00 75 00 72 00 65 00 41 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 79 00}  //weight: 10, accuracy: Low
        $x_10_3 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 79}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Dridex_GC_2147761787_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GC!MTB"
        threat_id = "2147761787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 64 a3 00 00 00 00 [0-20] 83 ec 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 4b 00 cc [0-12] cc [0-12] cc}  //weight: 10, accuracy: Low
        $x_2_2 = "FGtkemvb" ascii //weight: 2
        $x_2_3 = "RTTYEBHUY.pdb" ascii //weight: 2
        $x_2_4 = "ManyvversionndailykLitoranimal" ascii //weight: 2
        $x_2_5 = "ggploeER.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_GC_2147761787_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GC!MTB"
        threat_id = "2147761787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 64 a3 00 00 00 00 [0-15] 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 4b 00 cc [0-10] cc [0-10] cc}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 04 24 64 a3 00 00 00 00 [0-15] 83 ec 04 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 4b 00 cc [0-10] cc [0-10] cc}  //weight: 10, accuracy: Low
        $x_10_3 = {8b 04 24 64 a3 00 00 00 00 [0-15] 83 ec 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 4b 00 cc [0-10] cc [0-10] cc}  //weight: 10, accuracy: Low
        $x_2_4 = "bBOLLPIU" ascii //weight: 2
        $x_2_5 = "gpoiree" ascii //weight: 2
        $x_2_6 = "FGtkemvb" ascii //weight: 2
        $x_2_7 = ".pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_GD_2147761788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GD!MTB"
        threat_id = "2147761788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 8b 75 ?? 88 14 06 83 c0 ?? 89 45 ?? 8b 7d ?? 39 f8 [0-32] 8b 45 ?? 8b 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GD_2147761788_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GD!MTB"
        threat_id = "2147761788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 e8 f6 e2 88 44 24 ?? 8a 44 24 ?? 8b 74 24 ?? 81 e6 74 db 20 7e 89 74 24 ?? c7 44 24 ?? 00 00 00 00 8b 75 ?? 8b 7d ?? 88 04 37 8d 65}  //weight: 10, accuracy: Low
        $x_2_2 = "FFPGGLBM.pdb" ascii //weight: 2
        $x_2_3 = "Betatreeking3seecesesoeving.123forXemetif" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GD_2147761788_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GD!MTB"
        threat_id = "2147761788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VirtualProtect" ascii //weight: 1
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "rotect begin" ascii //weight: 1
        $x_1_4 = "//FileApi.gyao.top/002/pupp" ascii //weight: 1
        $x_1_5 = "HTTP/1.1" ascii //weight: 1
        $x_1_6 = "swsyqbERMQ1gswsyqbERMQ1gswsyqbERMQ1g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GD_2147761788_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GD!MTB"
        threat_id = "2147761788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d8 29 fb 88 d8 88 44 24 ?? 8a 44 24 ?? 8b 7d ?? 8b 5d ?? 88 04 1f}  //weight: 1, accuracy: Low
        $x_1_2 = "vSilverright18,capabilitiespopularitywinWindowsTheiloveyou" ascii //weight: 1
        $x_10_3 = {40 cc cc cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3}  //weight: 10, accuracy: Low
        $x_10_4 = "tttt32" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_ZV_2147764467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ZV"
        threat_id = "2147764467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 53 8b 00 3d fd 00 00 c0 77 14 74 ?? 3d 03 00 00 80 0f 84 6a 05 00 00 3d 05 00 00 c0 eb 05 3d 74 03 00 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_MS_2147766640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.MS!MTB"
        threat_id = "2147766640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "URLOpenStreamA" ascii //weight: 10
        $x_1_2 = "theWBinInFirefox" wide //weight: 1
        $x_1_3 = "aHDbyGoogle" wide //weight: 1
        $x_1_4 = "canariesnativedeterminedstellaGzWOfrom" wide //weight: 1
        $x_1_5 = "passChromevery1Chromium,ZitLrelease" wide //weight: 1
        $x_1_6 = "TweetDeckprefetchingandrweek,is" wide //weight: 1
        $x_1_7 = "5Chrome1On" wide //weight: 1
        $x_1_8 = "kGooglefasterof" wide //weight: 1
        $x_1_9 = "TheqlakerswebsitesUtabbusers" wide //weight: 1
        $x_1_10 = "ChromeLocaldevelopersoonGHeT" wide //weight: 1
        $x_1_11 = "red1237thecreated.cgpm" wide //weight: 1
        $x_1_12 = "notnpGoogle520132016,to" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_PJ_2147767099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PJ!MTB"
        threat_id = "2147767099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 9e 64 b3 82 42 ed fe 8d 6f 2d 0b 2b 01 59 ae d9 53 fd a0 51 c7 20 c1 9c 67 64 2b 1f 96 40 45 4a 1e e4 d2 83 2e ed 1e 0d a2 ac 3e 2b cd 8c c2}  //weight: 1, accuracy: High
        $x_1_2 = "HBITMAP_UserSize" ascii //weight: 1
        $x_1_3 = "PolylineTo" ascii //weight: 1
        $x_1_4 = "SwitchToThisWindow" ascii //weight: 1
        $x_1_5 = "LoadKeyboardLayoutA" ascii //weight: 1
        $x_1_6 = "OpenSemaphoreW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DA_2147767252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DA!MTB"
        threat_id = "2147767252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b bc 2e f5 e4 ff ff 75 ?? 04 1e 02 c0 2a 05 ?? ?? ?? ?? 02 c1 66 0f b6 d0 66 6b d2 03 66 2b 15 ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? 81 c7 d4 e0 08 01 89 3d ?? ?? ?? ?? 89 bc 2e f5 e4 ff ff 8a 15 ?? ?? ?? ?? 66 8b 0d ?? ?? ?? ?? 8a c2 02 c1 83 c6 04 2c 02 81 fe 33 1c 00 00 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DA_2147767252_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DA!MTB"
        threat_id = "2147767252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 1f 03 f0 2b d6 83 ea 57 6b c2 56 89 15 ?? ?? ?? ?? 2b c8 6b c7 56 89 0d ?? ?? ?? ?? 2b c8 2b d1 89 0d ?? ?? ?? ?? 8d 42 f7 03 c7 a3 ?? ?? ?? ?? 33 c0 89 45 3c 8d 45 30 89 45 40}  //weight: 10, accuracy: Low
        $x_3_2 = "Bearmass" ascii //weight: 3
        $x_3_3 = "Caselist" ascii //weight: 3
        $x_3_4 = "CommonWash" ascii //weight: 3
        $x_3_5 = "Heregather" ascii //weight: 3
        $x_3_6 = "Melodycross" ascii //weight: 3
        $x_3_7 = "Woodgirl" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DB_2147767275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DB!MTB"
        threat_id = "2147767275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 d9 03 1d ?? ?? ?? ?? 0f b7 d0 03 d3 89 15 ?? ?? ?? ?? 2a d0 80 c2 35 02 d2 02 ca 8a d0 2a 15 ?? ?? ?? ?? 81 c7 6c 2b 06 01 80 ea 4b 89 3d ?? ?? ?? ?? 89 bc 2e a3 f0 ff ff 02 ca 8b 15 ?? ?? ?? ?? 83 c6 04 81 fe 6d 10 00 00 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DB_2147767275_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DB!MTB"
        threat_id = "2147767275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Repddd4.pdb" ascii //weight: 3
        $x_3_2 = "DppottonErr" ascii //weight: 3
        $x_3_3 = "GetRawInputDeviceInfoW" ascii //weight: 3
        $x_3_4 = "GetKeyNameTextA" ascii //weight: 3
        $x_3_5 = "SetupDiGetDeviceInterfaceDetailA" ascii //weight: 3
        $x_3_6 = "MprInfoBlockRemove" ascii //weight: 3
        $x_3_7 = "GetTempFileNameW" ascii //weight: 3
        $x_3_8 = "WritePrivateProfileStructW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_MW_2147767770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.MW!MTB"
        threat_id = "2147767770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 5c 00 54 00 45 00 53 00 54 00 41 00 50 00 50 00 2e 00 45 00 58 00 45 00 00 00 50 00 50 00 2e 00 45 00 58 00 45 00 00 00 54 00 41 00 50 00 50 00 2e 00 45 00 58 00 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 3a 5c 5c 54 45 53 54 41 50 50 2e 45 58 45 00 50 50 2e 45 58 45 00 54 41 50 50 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_3 = "self.EXE" ascii //weight: 1
        $x_1_4 = "ESTAPP E_" wide //weight: 1
        $x_1_5 = "CM_Get_Device_ID_List_ExW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Dridex_DC_2147768785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DC!MTB"
        threat_id = "2147768785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c7 66 01 05 ?? ?? ?? ?? 8d 04 3f 2b c8 0f b7 c3 2b c6 89 0d ?? ?? ?? ?? 8b 4c 24 18 83 c0 06 a3 ?? ?? ?? ?? 8b 44 24 14 05 24 73 02 01 a3 ?? ?? ?? ?? 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DC_2147768785_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DC!MTB"
        threat_id = "2147768785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 08 03 32 8b 45 08 89 30 8b 4d f4 81 c1 ?? ?? ?? ?? 8b 55 08 8b 02 2b c1 8b 4d 08 89 01}  //weight: 10, accuracy: Low
        $x_10_2 = {03 4d c4 8b 15 ?? ?? ?? ?? 2b d1 89 15 ?? ?? ?? ?? b8 73 00 00 00 85 c0 0f 85 23}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PL_2147769342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PL!MTB"
        threat_id = "2147769342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ca 83 e2 ?? 88 [0-3] 8b [0-3] 8a [0-2] 2a [0-6] 04 20 8b [0-3] 88 [0-2] 83 [0-3] 89 [0-3] 8b [0-3] 39 f9 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_MX_2147770148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.MX!MTB"
        threat_id = "2147770148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {43 00 3a 00 5c 00 5c 00 54 00 45 00 53 00 54 00 41 00 50 00 50 00 2e 00 45 00 58 00 45 00 00 00 50 00 50 00 2e 00 45 00 58 00 45 00 00 00 54 00 41 00 50 00 50 00 2e 00 45 00 58 00 45 00}  //weight: 3, accuracy: High
        $x_3_2 = {43 3a 5c 5c 54 45 53 54 41 50 50 2e 45 58 45 00 50 50 2e 45 58 45 00 54 41 50 50 2e 45 58 45 00}  //weight: 3, accuracy: High
        $x_2_3 = "self.EXE" ascii //weight: 2
        $x_2_4 = "self.EXE" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_KM_2147770408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KM!MTB"
        threat_id = "2147770408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c3 05 e2 38 00 00 03 c6 8d 0c 48 0f b6 05 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 3b f0 74 ?? a0 ?? ?? ?? ?? 83 c2 02 83 fa 0d 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_KM_2147770408_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KM!MTB"
        threat_id = "2147770408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 e0 11 00 00 ff 15 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 0c 31 88 0c 02 8b 15 ?? ?? ?? ?? 83 c2 01 89 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_KM_2147770408_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KM!MTB"
        threat_id = "2147770408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d1 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 03 cf 89 4c 24 ?? 8b 31 8a 0d ?? ?? ?? ?? 80 e9 6b 02 d9 81 7c 24 ?? 08 1b 00 00 88 1d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_KM_2147770408_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KM!MTB"
        threat_id = "2147770408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be d1 66 89 d6 66 ?? ?? ?? ?? 89 c2 83 c2 01 8a 4c 05 ?? 8a 6d ?? 80 c5 a2 38 e9 88 4d ?? 89 55 ?? 74 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 1c 08 88 1c 0a 83 c1 01 89 4c 24 ?? 8b 44 24 ?? 39 c1 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_KM_2147770408_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KM!MTB"
        threat_id = "2147770408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 8c 10 16 02 00 00 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea 16 02 00 00 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ba 59 01 00 00 85 d2 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_KM_2147770408_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KM!MTB"
        threat_id = "2147770408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 1e 23 00 00 e8 ?? ?? ?? ?? 83 c4 04 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 94 01 ?? ?? ?? ?? 2b 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d 1e 23 00 00 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? a1 ?? ?? ?? ?? 2b c2 a3 ?? ?? ?? ?? b9 73 00 00 00 85 c9 0f 85 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SM_2147770448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SM!MSR"
        threat_id = "2147770448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\myapp.exe" ascii //weight: 1
        $x_1_2 = "ffffrfecee42t96b2872ta3y-141ar469c-55aa22rrvvPP1" wide //weight: 1
        $x_1_3 = {b9 0e 00 00 00 33 15 ?? ?? ?? 00 c7 05 ?? ?? ?? 00 ?? ?? ?? 00 01 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 8b 0d 1c dc 46 00 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NA_2147771229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NA!MTB"
        threat_id = "2147771229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "0t6-+C*Pd2+Wk!e+-.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NA_2147771229_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NA!MTB"
        threat_id = "2147771229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 08 5d c3 25 00 33 [0-5] c7 05 [0-8] 01 15 [0-4] a1 [0-4] 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c2 01 89 [0-5] eb 24 00 ff [0-5] 03 [0-5] 8b [0-5] 8b [0-5] 8a [0-3] 88 [0-3] 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NB_2147771355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NB!MTB"
        threat_id = "2147771355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {43 00 3a 00 5c 00 5c 00 53 00 45 00 4c 00 46 00 2e 00 45 00 58 00 45 00 00 00 4c 00 46 00 2e 00 45 00 58 00 45 00 00 00 53 00 45 00 4c 00 46 00 2e 00 45 00 58 00 45 00}  //weight: 8, accuracy: High
        $x_8_2 = {43 3a 5c 5c 53 45 4c 46 2e 45 58 45 00 4c 46 2e 45 58 45 00 53 45 4c 46 2e 45 58 45}  //weight: 8, accuracy: High
        $x_1_3 = "self.exE" ascii //weight: 1
        $x_1_4 = "estapp" wide //weight: 1
        $x_1_5 = "gernel3.dll" wide //weight: 1
        $x_1_6 = "BE@E" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 3 of ($x_1_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_NB_2147771355_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NB!MTB"
        threat_id = "2147771355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "blolebr.pdb" ascii //weight: 3
        $x_3_2 = "remotepg.dll" ascii //weight: 3
        $x_3_3 = "FormatMessageA" ascii //weight: 3
        $x_3_4 = "MapViewOfFile" ascii //weight: 3
        $x_3_5 = "InterlockedCompareExchange" ascii //weight: 3
        $x_3_6 = "GetProcessHeap" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NC_2147771393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NC!MTB"
        threat_id = "2147771393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 11 8b e5 5d c3 30 00 ff [0-5] 8f [0-5] 33 [0-5] c7 05 [0-8] 8b [0-3] 01 15 [0-4] 8b 0d [0-4] 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NC_2147771393_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NC!MTB"
        threat_id = "2147771393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ComeWood\\Farmquotientanswer.pdb" ascii //weight: 3
        $x_3_2 = "\\NewDoctor\\steadJump" ascii //weight: 3
        $x_3_3 = "ExitMainViaCRT" ascii //weight: 3
        $x_3_4 = "DecodePointer" ascii //weight: 3
        $x_3_5 = "SetEndOfFile" ascii //weight: 3
        $x_3_6 = "SystemFunction036" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ZZ_2147771658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ZZ!MTB"
        threat_id = "2147771658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 12 35 09 00 77 07 cc cc 40 cc cc eb f2}  //weight: 1, accuracy: High
        $x_1_2 = {77 07 cc cc 40 cc cc eb f2 05 00 3d ?? ?? 09 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_PM_2147771730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PM!MTB"
        threat_id = "2147771730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 52 86 e8 6c 19 4a d9 a5 df 5d db 30 b2 5e 39 ab e0 ff ae 41 f2 74 b7 b7 3e 70 1a e4 7d 50 33 bb d3 06 c8 eb e6 4a 58 a5 df 7d 27 30 e5 5e 25}  //weight: 4, accuracy: High
        $x_1_2 = "background.there1M518fire" ascii //weight: 1
        $x_1_3 = "GooglefuckmetheafterYJ" ascii //weight: 1
        $x_1_4 = "fortoFotherdFlashshare.30UinstanceChrome" ascii //weight: 1
        $x_1_5 = "iallowslater" ascii //weight: 1
        $x_1_6 = "websitestheU5launch" ascii //weight: 1
        $x_1_7 = "processesZsecurity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_NF_2147771867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NF!MTB"
        threat_id = "2147771867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 33 [0-6] c7 05 [0-8] 8b [0-6] 01 [0-6] 8b [0-6] 8b [0-6] 89 [0-6] 8b [0-6] 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NG_2147771907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NG!MTB"
        threat_id = "2147771907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 00 eb 00 8b [0-6] 33 [0-3] c7 05 [0-8] 8b [0-3] 01 [0-6] a1 [0-4] 8b 0d [0-4] 89 [0-3] 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NH_2147771915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NH!MTB"
        threat_id = "2147771915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 33 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b d1 01 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0c 31 88 0c 02 8b 15 ?? ?? ?? ?? 83 c2 01 89 15 ?? ?? ?? ?? eb 1d 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NE_2147772134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NE!MTB"
        threat_id = "2147772134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ESTAPP E_" wide //weight: 1
        $x_1_2 = "elf EX" wide //weight: 1
        $x_1_3 = "1ZModule,mechanisms1Sbc9W" wide //weight: 1
        $x_1_4 = "dpp|pp.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NE_2147772134_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NE!MTB"
        threat_id = "2147772134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 4d f7 88 ca 80 e2 e4 88 55 f7 8b 75 08 88 4d f7 83 fe 00 89 45 e8}  //weight: 10, accuracy: High
        $x_3_2 = "FFPGGLBM.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NI_2147772182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NI!MTB"
        threat_id = "2147772182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 89 10 8b 0d [0-4] 8b 15 [0-4] 8d [0-4] a3 [0-4] 8b 0d [0-4] 89 0d [0-4] 8b 15 [0-4] 89 15 [0-4] a1 [0-4] 83 c0 04 a3 [0-4] eb 00 e8 [0-4] 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NJ_2147772392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NJ!MTB"
        threat_id = "2147772392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 33 0d [0-4] c7 05 [0-8] 8b d1 01 15 [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 [0-4] 8b [0-4] 8d [0-6] 8b [0-4] 03 [0-4] 8b [0-4] 89 [0-4] 8b [0-4] 8b [0-4] 81 [0-5] 8b [0-4] 89 [0-5] a1 [0-4] 8b [0-5] 8d [0-3] 89 15 [0-4] a1 [0-4] a3 [0-4] 8b [0-5] 89 [0-5] 8b [0-5] 83 [0-4] 89 [0-5] eb 00 e8 [0-4] 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_PN_2147773017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PN!MTB"
        threat_id = "2147773017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 41 89 ?? 83 ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 0f 84 ?? ?? ?? ?? 8b ?? ?? ?? 83 ?? ?? 8b ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 0f 84 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_KMG_2147773022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KMG!MTB"
        threat_id = "2147773022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 89 15 ?? ?? ?? ?? 8b 44 24 ?? 80 c3 16 89 35 ?? ?? ?? ?? 0f b7 c9 8b 84 28 ?? ?? ?? ?? 89 44 24 ?? 88 1d ?? ?? ?? ?? 81 ff d0 00 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_KMG_2147773022_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KMG!MTB"
        threat_id = "2147773022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca 0f b6 05 ?? ?? ?? ?? 3b f0 74 ?? 28 99 ?? ?? ?? ?? b8 a5 ff 00 00 2b c7 2b c6 8b f8 49 83 f9 01 7f}  //weight: 1, accuracy: Low
        $x_1_2 = {8a eb 39 05 ?? ?? ?? ?? 74 ?? 28 9a ?? ?? ?? ?? b0 a5 2a 05 ?? ?? ?? ?? 2a c1 8a c8 4a 83 fa 01 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GKM_2147773336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GKM!MTB"
        threat_id = "2147773336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 18 88 13 8d 14 b1 03 d6 4f 8d 54 3a ?? 66 89 15 ?? ?? ?? ?? 0f b7 d2 8d 14 92 c1 e2 04 2b d1 43 03 f2 85 ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GKM_2147773336_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GKM!MTB"
        threat_id = "2147773336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 28 88 55 00 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 8b ce 2b 0d ?? ?? ?? ?? 4b 83 e9 02 4f 45 89 5c 24 ?? 89 0d ?? ?? ?? ?? 81 fa 3e 02 00 00 74 ?? 8a 15 ?? ?? ?? ?? 2a 15 ?? ?? ?? ?? 02 d1 88 15 ?? ?? ?? ?? 8b cf 2b ce 81 e9 88 e1 00 00 8b f1 85 db 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GKM_2147773336_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GKM!MTB"
        threat_id = "2147773336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a d1 80 ea 4e 02 da 8b 15 ?? ?? ?? ?? 8b 8c 02 ?? ?? ?? ?? 81 c1 04 70 01 01 89 8c 02 ?? ?? ?? ?? 83 c0 04 89 0d ?? ?? ?? ?? 8d 74 3e ?? 0f b7 cd 3d 02 12 00 00 72}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d5 8d b4 3a ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 84 0a ?? ?? ?? ?? 05 9c 11 0e 01 89 84 0a ?? ?? ?? ?? 83 c1 04 a3 ?? ?? ?? ?? 81 f9 f0 0e 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_GKM_2147773336_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GKM!MTB"
        threat_id = "2147773336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 1e 23 00 00 e8 ?? ?? ?? ?? 83 c4 04 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 84 0a ?? ?? ?? ?? 2b 45 ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 e9 1e 23 00 00 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 2b c8 89 0d ?? ?? ?? ?? ba 73 00 00 00 85 d2 0f 85 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NM_2147773710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NM!MTB"
        threat_id = "2147773710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VubeLntestingyRpperformed" ascii //weight: 1
        $x_1_2 = "onPhiddennew" ascii //weight: 1
        $x_1_3 = "Hijamesonw" ascii //weight: 1
        $x_1_4 = "startedbqengine" ascii //weight: 1
        $x_1_5 = "typing7forSome" ascii //weight: 1
        $x_1_6 = "them.165thirdMainz5bB" ascii //weight: 1
        $x_5_7 = {89 ca 83 e2 ?? 8b [0-6] 8a [0-2] 2a [0-6] 00 e0 88 [0-2] 83 [0-6] 89 [0-13] 39 ?? b0 ?? 8b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_NN_2147774285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NN!MTB"
        threat_id = "2147774285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ESTAPP E_" ascii //weight: 1
        $x_1_2 = "elf EX" ascii //weight: 1
        $x_1_3 = "underCqan5" ascii //weight: 1
        $x_1_4 = "FPOLM.pdb" ascii //weight: 1
        $x_1_5 = "SurgeonsHz" ascii //weight: 1
        $x_1_6 = "pfrankbrowsers.runA" ascii //weight: 1
        $x_1_7 = "support.Lmonthly,mofflineandhelp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Dridex_PO_2147775373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PO!MTB"
        threat_id = "2147775373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 18 8b [0-3] ba [0-4] f7 ?? 69 [0-5] 01 ?? 89 [0-3] 89 [0-3] 8b [0-3] 83 [0-2] 89 [0-3] 8b [0-3] 8b [0-2] 8b [0-3] 2b [0-3] 89 [0-3] 80 [0-3] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NP_2147776068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NP!MTB"
        threat_id = "2147776068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 a1 [0-6] 33 ?? c7 05 [0-8] 01 [0-5] a1 [0-4] 8b [0-5] 89 08 8b [0-3] 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NT_2147776529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NT!MTB"
        threat_id = "2147776529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 a1 [0-6] 89 [0-5] 31 [0-5] c7 05 [0-8] 8b [0-5] 01 [0-5] a1 [0-4] 8b [0-5] 89 08 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NU_2147776606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NU!MTB"
        threat_id = "2147776606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 18 35 [0-4] 89 [0-3] eb ?? 8b [0-3] 83 [0-2] 89 [0-3] 8b [0-2] 8b [0-3] 80 [0-3] 75 e8 8b [0-3] 8d [0-2] 5e 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {01 c1 88 ca 88 [0-5] 66 8b [0-2] 8b [0-2] 8b [0-2] 89 [0-5] 8a [0-5] 66 29 ?? 66 89 [0-2] 8b [0-5] 88 [0-2] 8b [0-5] 03 [0-2] 89 [0-2] 8b [0-2] 39 [0-2] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_NV_2147777000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NV!MTB"
        threat_id = "2147777000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 a1 [0-6] a3 [0-4] 33 [0-5] c7 05 [0-8] 01 [0-5] a1 [0-4] 8b [0-5] 89 08 8b ?? 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NW_2147777009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NW!MTB"
        threat_id = "2147777009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 10 39 [0-3] 8b [0-6] 8b [0-3] 8b [0-3] 35 [0-4] 83 [0-2] 01 ?? 8a [0-2] 88 [0-3] 8a [0-6] 22 [0-6] 88 [0-6] 8b [0-3] 89 [0-2] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_NX_2147777403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NX!MTB"
        threat_id = "2147777403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 00 eb 00 8b [0-5] 33 ?? 8b ?? a3 [0-4] a1 [0-4] 8b [0-5] 89 08 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_MV_2147777414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.MV!MTB"
        threat_id = "2147777414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f0 81 c1 [0-8] 8a 55 eb 8b 75 dc 80 f2 9c 88 55 eb 89 75 e4 8b 75 e4 8b 7d cc 89 7d ec 89 4d e0 8b 4d e4 8b 5d d4 8a 14 33 8b 75 e0 8b 7d d0 88 14 0f 39 f0}  //weight: 1, accuracy: Low
        $x_1_2 = "dntdll.dll" ascii //weight: 1
        $x_1_3 = "SELF.EXE" wide //weight: 1
        $x_1_4 = "ESTAPP E_" wide //weight: 1
        $x_1_5 = "Bookmarks(alsoigLinux,seeKwereanddue visitedFirefoxbycriticizedexplainingthemeasureseparateinfiniteversion" wide //weight: 1
        $x_1_6 = "Xbugs.184nativethatnatusingD" wide //weight: 1
        $x_1_7 = "mechanisms.108eitn(asa" wide //weight: 1
        $x_1_8 = "introducedon0manipulationsranger9xasksOctober" wide //weight: 1
        $x_1_9 = "gtheInternetsupportmartinthee" wide //weight: 1
        $x_1_10 = "pluginsuserwantNPAPIMicrosoftrsee" wide //weight: 1
        $x_1_11 = "JavaScriptreferson2011,CSS.163hJuneO" wide //weight: 1
        $x_1_12 = "D7nAsandH" wide //weight: 1
        $x_1_13 = {74 00 72 00 65 00 74 00 75 00 72 00 6e 00 2e 00 61 00 6e 00 64 00 72 00 65 00 66 00 65 00 72 00 73 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 63 00 62 00 65 00 36 00 95 00}  //weight: 1, accuracy: High
        $x_1_14 = "CM_Get_Device_ID_List_ExW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Dridex_NY_2147777451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NY!MTB"
        threat_id = "2147777451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {8b 4c 24 40 8a [0-6] 32 [0-6] 8b [0-6] 88 [0-6] 0f [0-3] 0f [0-7] 29 ?? 8b [0-6] 89 [0-2] 89 [0-3] 89 [0-3] e8}  //weight: 8, accuracy: Low
        $x_1_2 = "self.ex" ascii //weight: 1
        $x_1_3 = "Avira GmbH" ascii //weight: 1
        $x_1_4 = "fer6e5.pdb" ascii //weight: 1
        $x_1_5 = "RegLoadAppKeyW" ascii //weight: 1
        $x_1_6 = "OutputDebugStringA" ascii //weight: 1
        $x_1_7 = "Dbnoeeufhthra Fhatx" ascii //weight: 1
        $x_1_8 = "manipulationsvfredtheHighremovedf9" ascii //weight: 1
        $x_1_9 = "SadMChromiumversion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_NZ_2147777452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.NZ!MTB"
        threat_id = "2147777452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "restrict(" ascii //weight: 1
        $x_1_2 = "\\kingPaint\\box.pdb" ascii //weight: 1
        $x_1_3 = "_nextafter" ascii //weight: 1
        $x_1_4 = "Wordable" ascii //weight: 1
        $x_1_5 = "Saidcause" ascii //weight: 1
        $x_1_6 = "DllRegisterServer" ascii //weight: 1
        $x_1_7 = "AlphaBlend" ascii //weight: 1
        $x_1_8 = "TransparentBlt" ascii //weight: 1
        $x_1_9 = "GradientFill" ascii //weight: 1
        $x_1_10 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_11 = "http://www.washroad.com" ascii //weight: 1
        $x_1_12 = "?h?p?x?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PP_2147777664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PP!MTB"
        threat_id = "2147777664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eszfirstCand7Unique9" ascii //weight: 1
        $x_1_2 = "backgrourd.there1M518fire" ascii //weight: 1
        $x_1_3 = "thatPnew" ascii //weight: 1
        $x_1_4 = "iallowslater" ascii //weight: 1
        $x_1_5 = "Adblockfeaturesf36%u4BKA" ascii //weight: 1
        $x_1_6 = "w2jconnecteddwithw3,once" ascii //weight: 1
        $x_1_7 = "markGoogleZlogsa" ascii //weight: 1
        $x_1_8 = "Chromecorelease" ascii //weight: 1
        $x_1_9 = "Dbvv.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PR_2147777666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PR!MTB"
        threat_id = "2147777666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 31 05 [0-4] c7 05 [0-8] 8b 15 [0-4] 01 15 [0-4] a1 [0-4] 8b 0d [0-4] 89 08 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OB_2147777674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OB!MTB"
        threat_id = "2147777674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stretchWide\\100_Else\\theseMore\\MonthFind\\Least.pdb" ascii //weight: 1
        $x_1_2 = "Mightcow" ascii //weight: 1
        $x_1_3 = "Onlyread" ascii //weight: 1
        $x_1_4 = "_nextafter" ascii //weight: 1
        $x_1_5 = "CONOUT$" ascii //weight: 1
        $x_1_6 = "AlphaBlend" ascii //weight: 1
        $x_1_7 = "TransparentBlt" ascii //weight: 1
        $x_1_8 = "GradientFill" ascii //weight: 1
        $x_1_9 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_10 = "?h?p?x?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GT_2147777776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GT!MTB"
        threat_id = "2147777776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 ce 03 c1 81 c7 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 bb ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 ?? 8d 14 29 8b 4c 24 ?? 83 c1 04 03 d0 89 15 ?? ?? ?? ?? 89 4c 24 ?? 81 f9 ?? ?? ?? ?? 73}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GT_2147777776_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GT!MTB"
        threat_id = "2147777776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {54 89 e7 89 17 c7 47 ?? 01 00 00 00 c7 47 ?? 00 00 00 00 8b 15 ?? ?? ?? ?? 89 4c 24 ?? ff d2}  //weight: 10, accuracy: Low
        $x_10_2 = {cc cc 40 cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3}  //weight: 10, accuracy: Low
        $x_10_3 = "ESTAPPPexe" ascii //weight: 10
        $x_1_4 = "tttt32" ascii //weight: 1
        $x_1_5 = "OutputDebugStringA" ascii //weight: 1
        $x_1_6 = "CreatePointerMoniker" ascii //weight: 1
        $x_1_7 = "Xhot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_OD_2147777796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OD!MTB"
        threat_id = "2147777796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {8b 44 24 08 05 [0-4] 8b [0-3] 83 [0-2] 89 [0-3] 89 [0-3] 8b [0-3] 35 [0-4] 8b [0-3] 8b [0-3] 81 [0-5] 8b [0-3] 83 [0-2] 89 [0-3] 89 [0-3] 01 ?? 89 [0-3] 8a [0-3] 88 [0-3] eb}  //weight: 7, accuracy: Low
        $x_1_2 = "Bthemaddress" ascii //weight: 1
        $x_1_3 = "basicthemesGoogle" ascii //weight: 1
        $x_1_4 = "FEdownloadingEdue" ascii //weight: 1
        $x_1_5 = "8four-part8Chrome,ZSMtheirX" ascii //weight: 1
        $x_1_6 = "OutputDebugStringA" ascii //weight: 1
        $x_1_7 = "Chromestring,kare3" ascii //weight: 1
        $x_1_8 = "Avira GmbH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_PAB_2147778064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PAB!MTB"
        threat_id = "2147778064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ipreinstalled,theunlikemonbond007simplifiedBak" ascii //weight: 1
        $x_1_2 = "ChromeAwasGoogleunstablebyninetheGoogle" ascii //weight: 1
        $x_1_3 = "systemLYeencourageVcani" wide //weight: 1
        $x_1_4 = "LocalOmniboxtheZHonly" wide //weight: 1
        $x_1_5 = "grantkzinteractivity" ascii //weight: 1
        $x_1_6 = "updatesuSpeed" wide //weight: 1
        $x_1_7 = "Icmp6SendEcho2" ascii //weight: 1
        $x_1_8 = "AntiVir" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OH_2147778187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OH!MTB"
        threat_id = "2147778187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 61 8a 4c 24 ?? 80 [0-2] 8b [0-3] 88 [0-3] 8b [0-2] 66 8b [0-3] 66 89 [0-3] 03 [0-2] 8a [0-3] 89 [0-3] 8b [0-3] 89 [0-3] 8b [0-2] 8b [0-2] 03 [0-3] 89 [0-3] 8a [0-3] 80 [0-2] 88 [0-3] 8b [0-3] 2b [0-3] 8b [0-2] 89 [0-3] 8b [0-2] 89 [0-3] 38 c8 72}  //weight: 1, accuracy: Low
        $x_1_2 = "_es__pp____" ascii //weight: 1
        $x_1_3 = "OutputDebugStringA" ascii //weight: 1
        $x_1_4 = "self.ex" ascii //weight: 1
        $x_1_5 = "Avira GmbH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OJ_2147778675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OJ!MTB"
        threat_id = "2147778675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e6 89 16 89 [0-3] e8 [0-4] 8b [0-3] 01 ?? 88 ?? 8b [0-3] 89 [0-6] 8b [0-3] 89 [0-6] 88 [0-3] 66 8b [0-6] 66 8b [0-6] 8a [0-3] 8b [0-2] 66 29 fe 66 89 [0-6] 8b [0-3] c7 [0-10] 66 8b [0-6] 66 83 [0-2] 66 89 [0-6] 88 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OK_2147778740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OK!MTB"
        threat_id = "2147778740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-es--pp----" ascii //weight: 1
        $x_1_2 = "GTRG.pdb" ascii //weight: 1
        $x_1_3 = "self.ex" ascii //weight: 1
        $x_1_4 = "Avira GmbH" ascii //weight: 1
        $x_1_5 = "RSDSa" ascii //weight: 1
        $x_1_6 = "GenerateConsoleCtrlEvent" ascii //weight: 1
        $x_1_7 = "OutputDebugStringA" ascii //weight: 1
        $x_1_8 = "RegisterDeviceNotificationW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OL_2147778769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OL!MTB"
        threat_id = "2147778769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-es--pp----" ascii //weight: 1
        $x_1_2 = "#P#E#E#T#P#.#X#" ascii //weight: 1
        $x_1_3 = "GTRG.pdb" ascii //weight: 1
        $x_1_4 = "self.ex" ascii //weight: 1
        $x_1_5 = "Avira GmbH" ascii //weight: 1
        $x_1_6 = "GenerateConsoleCtrlEvent" ascii //weight: 1
        $x_1_7 = "OutputDebugStringA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OM_2147778791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OM!MTB"
        threat_id = "2147778791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 08 8b e5 5d c3 21 00 33 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 89 0a a1 [0-4] 8b [0-5] 8d [0-6] 89 [0-5] a1 [0-4] a3 [0-4] 8b [0-5] 89 [0-5] 8b [0-5] 83 [0-2] 89 [0-5] e8 [0-4] 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AR_2147779032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AR!MSR"
        threat_id = "2147779032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\made\\Name\\oh\\gentle\\Solution_one\\use.pdb" ascii //weight: 5
        $x_5_2 = "\\Chord-felt\\668\\Wrong\\767\\Soldier-stream\\Good.pdb" ascii //weight: 5
        $x_5_3 = "\\Season\\Wife_low\\531\\Quart\\table.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_PAC_2147779675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PAC!MTB"
        threat_id = "2147779675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\try\\Fair\\Did-miss\\Neigh\\Deep.pdb" ascii //weight: 1
        $x_1_2 = "Deep.dll" ascii //weight: 1
        $x_1_3 = {8b 0d 04 a0 05 01 56 57 bf 4e e6 40 bb be 00 00 ff ff 3b cf 74 04 85 ce 75 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OR_2147779870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OR!MTB"
        threat_id = "2147779870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 eb 00 a1 [0-4] a3 [0-4] 8b 0d [0-4] 8b 11 89 15 [0-4] 8b 0d [0-4] a1 [0-4] a3 [0-4] 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {89 08 8b e5 5d c3 21 00 33 15 [0-4] c7 05 [0-8] 01 15 [0-4] a1 [0-4] 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OS_2147779902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OS!MTB"
        threat_id = "2147779902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e2 89 32 89 [0-3] 89 [0-3] e8 [0-4] 8b [0-3] 81 [0-5] 8b [0-3] 89 [0-6] 89 [0-6] 8b [0-3] 01 c1 c7 [0-10] c7 [0-10] 88 c8 88 [0-3] 8a [0-3] 28 c0 88 [0-6] 8b [0-3] 8a [0-3] 8b [0-3] 8b [0-3] 89 [0-6] 88 [0-2] 8a [0-3] 34 ?? 88 [0-6] eb 10 c7 [0-10] e9 [0-4] 8b [0-3] 8b [0-3] 81 [0-5] 89 [0-6] 03 [0-3] c7 [0-10] 89 [0-3] eb 18 8b [0-3] 35 [0-4] 89 [0-6] 8d [0-3] 5e 5f 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OT_2147779903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OT!MTB"
        threat_id = "2147779903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e1 89 01 e8 [0-4] 8b [0-6] 8b [0-2] 0f [0-3] 8b [0-3] 0f [0-4] 29 f9 89 e7 89 37 89 [0-3] 89 [0-3] e8 [0-4] c6 [0-7] 8b [0-3] 01 c1 88 ca 88 [0-6] 8a [0-6] 8b 45 08 c7 [0-10] c7 [0-10] 8b [0-6] 88 14 08 eb 7c 66 8b [0-3] 66 35 [0-2] 66 89 [0-3] 8b [0-3] 89 e2 89 0a e8 [0-4] 0f [0-4] 01 c9 66 89 ?? 66 89 [0-3] 8b [0-6] 8b 55 08 81 [0-5] 89 [0-6] 8b [0-6] 0f [0-3] 29 c7 89 f8 88 c3 88 1c 0a eb 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OU_2147780048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OU!MTB"
        threat_id = "2147780048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 08 5b 8b e5 5d c3 21 00 33 1d [0-4] c7 05 [0-8] 01 [0-5] a1 [0-4] 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 53 eb 00 a1 [0-4] a3 [0-4] 8b 0d [0-4] 8b 11 89 15 [0-4] 8b 0d [0-4] a1 [0-4] a3 [0-4] 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ADF_2147780097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ADF!MTB"
        threat_id = "2147780097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 00 c5 d0 18 c5 2e 26 e1 ca a9 f1 9e 12 14 1b c3 f0 2a cf ec ee 46 18 c4 ab 57 a5 51 40 7c fe 4a 78 b1 f0 18 45 fb 07 e1 ca 75 f2 bd 12 34 e7 a3 f0 a9 4f b9 4e 45 f9 e4 de 43 91 51 2c 7c fd}  //weight: 10, accuracy: High
        $x_3_2 = "--s--pp----" ascii //weight: 3
        $x_3_3 = "Gsp.pdb" ascii //weight: 3
        $x_1_4 = "#:#\\#E#T#P#.#X#" ascii //weight: 1
        $x_1_5 = "#P#E#E#T#P#.#X#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_AFC_2147780098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AFC!MTB"
        threat_id = "2147780098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {9e d9 30 dd 1f 7c 7e 9a a6 b0 5f 36 74 03 40 c8 90 80 8e 5e f7 42 2c 56 fa 74 b1 fd 97 38 6c 3c 6b d9 31 dd d3 af fe 9b a6 10 92 36 88 03 a0 c8 11 34 c2 3f e3 42 0c 56 19 55 32 b1 97 38 6c bb}  //weight: 10, accuracy: High
        $x_3_2 = "--s--pp----" ascii //weight: 3
        $x_3_3 = "Gsp.pdb" ascii //weight: 3
        $x_1_4 = "#:#\\#E#T#P#.#X#" ascii //weight: 1
        $x_1_5 = "#P#E#E#T#P#.#X#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_ADX_2147780099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ADX!MTB"
        threat_id = "2147780099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 00 3c 8f 4e 70 5e 6a 40 22 37 5c 30 7e c8 20 10 bc ed b6 81 e4 14 ce 47 d6 d9 5b 47 71 46 6a f5 68 88 db 81 10 5e 6a 73 82 17 5c e4 7e b4 6c 90 bc 6c b6 b5 b0 34 6e 47 d6 d9 0f c8 52 46 6a}  //weight: 10, accuracy: High
        $x_3_2 = "--s--pp----" ascii //weight: 3
        $x_3_3 = "Gsp.pdb" ascii //weight: 3
        $x_1_4 = "CryptCATAdminCalcHashFromFileHandle" ascii //weight: 1
        $x_1_5 = "#P#E#E#T#P#.#X#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_AMD_2147780100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AMD!MTB"
        threat_id = "2147780100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {7a 69 a5 0f 08 e8 c2 8b af 0b 63 78 98 28 fd 1b 52 6b 23 a7 df 08 a4 dd 49 6d 01 94 34 ca 1c 2b 7a 09 b9 0f 1c 9c 76 57 8f 0b 64 79 19 88 1c bb 33 9f 23 28 ff e8 44 dd 16 ec b5 b3 35 e9 e8 3f}  //weight: 10, accuracy: High
        $x_3_2 = ",,s,,pp,,,e" ascii //weight: 3
        $x_3_3 = "fffp4.pdb" ascii //weight: 3
        $x_1_4 = "#:#\\#E#T#P#.#X#" ascii //weight: 1
        $x_1_5 = "#P#E#E#T#P#.#X#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_AMB_2147780101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AMB!MTB"
        threat_id = "2147780101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8e 13 fa 26 54 57 3f 5c 48 71 8e bb 39 a7 fb f6 12 40 59 bc 02 a2 ae 57 4b 58 93 ef 74 2c 99 4b 2e 13 da 59 40 b7 0b 5c 48 71 7a 3b 39 bb fc f7 45 21 78}  //weight: 10, accuracy: High
        $x_3_2 = "OutputDebugStringA" ascii //weight: 3
        $x_3_3 = "CreateStreamOnHGlobal" ascii //weight: 3
        $x_1_4 = "#:#\\#E#T#P#.#X#" ascii //weight: 1
        $x_1_5 = "#P#E#E#T#P#.#X#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_OV_2147780301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OV!MTB"
        threat_id = "2147780301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 5c 8b 4c 24 4c 83 e1 1f 83 c1 00 8a 54 24 1b 80 ea 8c 88 [0-6] 8a 14 08 88 54 24 43 8b 44 24 5c 89 04 24 e8 0e e9 ff ff b2 70 8b 4c 24 4c 8a 74 24 1b 28 f2 8b 75 0c 88 [0-6] 8b 7c 24 5c 8a 14 0e 8a 5c 24 43 0f b6 ca 0f b6 f3 29 f1 89 3c 24 89 44 24 08 89 4c 24 04 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PB_2147780313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PB!MTB"
        threat_id = "2147780313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DartingDluginZ2015" ascii //weight: 1
        $x_1_2 = "He2DoogleB9x" ascii //weight: 1
        $x_1_3 = "numberthem" ascii //weight: 1
        $x_1_4 = "DDdefaults" ascii //weight: 1
        $x_1_5 = "nnnvepvmdgh.dll" ascii //weight: 1
        $x_1_6 = "fpmvppp.pdb" ascii //weight: 1
        $x_1_7 = "Oracle Corporation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PB_2147780313_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PB!MTB"
        threat_id = "2147780313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "nnnvepvmdgh.dll" ascii //weight: 1
        $x_1_2 = "FGERN.pdb" ascii //weight: 1
        $x_1_3 = "x2otfb.dll" wide //weight: 1
        $x_2_4 = {81 f1 80 8e b2 16 8b 94 24 ?? ?? ?? ?? 8b b4 24 ?? ?? ?? ?? 8b 7c 24 ?? 89 bc 24 ?? ?? ?? ?? 89 8c 24 ?? ?? ?? ?? 89 e1 [0-37] 8b 45 ?? 8b 8c 24 ?? ?? ?? ?? 01 c8 8a 9c 24 ?? ?? ?? ?? b7 cb 28 df 88 bc 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 8b 44 24 ?? 35 25 0a fc 52}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EDS_2147780447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EDS!MTB"
        threat_id = "2147780447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "y1891theWasservedm4" ascii //weight: 2
        $x_2_2 = "He2GoogleB9x" ascii //weight: 2
        $x_2_3 = "tartingPluginZ2015" ascii //weight: 2
        $x_2_4 = "RtplDtpmimr67" ascii //weight: 2
        $x_2_5 = "tttt32" ascii //weight: 2
        $x_2_6 = "FTBUP.pdb" ascii //weight: 2
        $x_2_7 = "GgolferABcopyversiontopassvideo" ascii //weight: 2
        $x_2_8 = "InandChromeCbehavemnumbervconstituency.5" ascii //weight: 2
        $x_2_9 = "kernel32.Sleep" ascii //weight: 2
        $x_2_10 = "OutputDebugStringA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Trojan_Win32_Dridex_OW_2147780540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OW!MTB"
        threat_id = "2147780540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 08 5b 8b e5 5d c3 23 00 8b [0-5] 33 ?? c7 05 [0-8] 01 [0-5] a1 [0-4] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RT_2147780548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RT!MTB"
        threat_id = "2147780548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d3 c7 05 ?? ?? ?? ?? 00 00 00 00 01 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5b 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RT_2147780548_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RT!MTB"
        threat_id = "2147780548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XfuckmesbenU" ascii //weight: 1
        $x_1_2 = "g1shit2astested,uT" ascii //weight: 1
        $x_1_3 = "yfuckoffwpC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RT_2147780548_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RT!MTB"
        threat_id = "2147780548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MapVirtualKeyW" ascii //weight: 1
        $x_1_2 = "LoadKeyboardLayoutA" ascii //weight: 1
        $x_1_3 = "PolylineTo" ascii //weight: 1
        $x_1_4 = "ArcTo" ascii //weight: 1
        $x_1_5 = "GetSecurityDescriptorGroup" ascii //weight: 1
        $x_1_6 = "@shell32.dll" ascii //weight: 1
        $x_1_7 = "l32.dll" ascii //weight: 1
        $x_1_8 = "SCardDisconnect" ascii //weight: 1
        $x_1_9 = "midiStreamClose" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RT_2147780548_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RT!MTB"
        threat_id = "2147780548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c0 5a 03 c6 89 0d ?? ?? ?? ?? 89 44 24 ?? 81 7c 24 ?? cd 05 00 00 75 ?? 66 0f b6 05 ?? ?? ?? ?? 66 03 e8 0f b7 c5 66 89 6c 24 ?? 8d 5c 43 ?? 0f b6 05 ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? 03 c6 3d 7c 03 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = "c:\\Cause\\417\\Organ\\Out vi\\grand.pdb" ascii //weight: 1
        $x_1_3 = "GetStartupInfoA" ascii //weight: 1
        $x_1_4 = "essi\"e C2ei1" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RT_2147780548_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RT!MTB"
        threat_id = "2147780548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Qtranslationgirlsy8Hdthatinformationto" ascii //weight: 1
        $x_1_2 = "onlyandintroducedGoogleimplementedvulnerabilitiesChrometermed" ascii //weight: 1
        $x_1_3 = "X0Mozillaslater2auto-updatefwas8" ascii //weight: 1
        $x_1_4 = "oz1951monicascorespussyepChromium6" ascii //weight: 1
        $x_1_5 = "ggploeER.dl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Dridex_OX_2147780648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OX!MTB"
        threat_id = "2147780648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "estapppEXE" ascii //weight: 1
        $x_1_2 = "QDdefaults" ascii //weight: 1
        $x_1_3 = "Oracle Corporation" ascii //weight: 1
        $x_1_4 = "j2pcsc.dll" ascii //weight: 1
        $x_1_5 = "tartingPluginZ2015" ascii //weight: 1
        $x_1_6 = "He2GoogleB9x" ascii //weight: 1
        $x_1_7 = "numberthem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ANM_2147780659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ANM!MTB"
        threat_id = "2147780659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {94 80 07 75 ab ee 4b 9d 2b 02 67 8d 84 14 9c 4d 00 1a e8 ee af d0 5f db eb 8a 47 e8 ba c4 8b ad 94 60 1b 61 ab ee 17 e9 4b 22 66 d9 65 94 69 99 33 1a 48 8e 30 4f 13 a7 6a aa 5b e8 ba 10 8b cd}  //weight: 10, accuracy: High
        $x_4_2 = "tttt32" ascii //weight: 4
        $x_4_3 = "Fbmgpod43" ascii //weight: 4
        $x_4_4 = "pvldb.pdb" ascii //weight: 4
        $x_4_5 = "GgolferABcopyversiontopassvideo" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OY_2147780669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OY!MTB"
        threat_id = "2147780669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ES APP E_" ascii //weight: 1
        $x_1_2 = "elf EX" ascii //weight: 1
        $x_1_3 = "CryptImportPublicKeyInfo" ascii //weight: 1
        $x_1_4 = "ShowOwnedPopups" ascii //weight: 1
        $x_1_5 = "WinSCard.dll" ascii //weight: 1
        $x_1_6 = "SETUPAPI.dll" ascii //weight: 1
        $x_1_7 = "IIDFromString" ascii //weight: 1
        $x_1_8 = "UrlCanonicalizeA" ascii //weight: 1
        $x_1_9 = "cUyGoogle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_OZ_2147780682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.OZ!MTB"
        threat_id = "2147780682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "estapppEXE" ascii //weight: 1
        $x_1_2 = "numberthem" ascii //weight: 1
        $x_1_3 = "tartingPluginZ2015" ascii //weight: 1
        $x_1_4 = "8Facebook,sWs" ascii //weight: 1
        $x_1_5 = "providesbox3fora" ascii //weight: 1
        $x_1_6 = "CLUSAPI.dll" ascii //weight: 1
        $x_1_7 = "x2otfb.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AMK_2147780819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AMK!MTB"
        threat_id = "2147780819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "LoxmtYt" ascii //weight: 5
        $x_4_2 = "FGERN.pdb" ascii //weight: 4
        $x_3_3 = "providesbox3fora" ascii //weight: 3
        $x_3_4 = "He2GoogleB9x" ascii //weight: 3
        $x_3_5 = "y1891theWasservedm4" ascii //weight: 3
        $x_3_6 = "8Facebook,sWs" ascii //weight: 3
        $x_3_7 = "RasGetConnectionStatistics" ascii //weight: 3
        $x_3_8 = "RegOverridePredefKey" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_TEM_2147780820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.TEM!MTB"
        threat_id = "2147780820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 e0 52 79 9b 79 f1 3b eb 4c 40 53 45 7e a4 25 12 01 dc 10 a5 84 b6 07 8c 2a 29 cf 51 71 30 9e 78 f4 b2 fa cf 65 72 9b 6b cd 8c d3 91 1e a4 59 92 01 dc fc 24 51 36 26 ac 2a f5 02 50 90 7c ea}  //weight: 10, accuracy: High
        $x_3_2 = "Rpkder336" ascii //weight: 3
        $x_3_3 = "FGERN.pdb" ascii //weight: 3
        $x_2_4 = "y1891theWasservedm4" ascii //weight: 2
        $x_2_5 = "GgolferABcopyversiontopassvideo" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_TMZ_2147780821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.TMZ!MTB"
        threat_id = "2147780821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c2 15 36 da f4 df 85 92 a6 00 bb 55 d6 3e 21 4b de 12 fd cb 2a e8 70 ab 01 cc c1 af 47 00 d4 3a 22 16 16 7a 28 c0 99 a6 a6 20 db d5 8a 1e 40 ca de 91 31 ab ca b5 5c 97 80 4c f5 9b c7 00 d4 b9}  //weight: 10, accuracy: High
        $x_3_2 = "Rpkder336" ascii //weight: 3
        $x_3_3 = "FGERN.pdb" ascii //weight: 3
        $x_2_4 = "InandChromeCbehavemnumbervconstituency.5" ascii //weight: 2
        $x_2_5 = "GgolferABcopyversiontopassvideo" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_TNT_2147780822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.TNT!MTB"
        threat_id = "2147780822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {18 90 86 27 4d 0c 6b 27 87 52 82 9c 04 5f 99 54 8e ee a2 4b 9a 42 26 d4 7b f5 c8 48 c7 16 04 06 4b 5c a5 f4 cd ac 6b 08 67 d2 02 9c 64 5e f9 f4 c1 ee c1 18 1b 2e a6 d4 9a 76 14 48 a7 e2 f0 06}  //weight: 10, accuracy: High
        $x_3_2 = "Rpkder336" ascii //weight: 3
        $x_3_3 = "FGERN.pdb" ascii //weight: 3
        $x_2_4 = "y1891theWasservedm4" ascii //weight: 2
        $x_2_5 = "InandChromeCbehavemnumbervconstituency.5" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GU_2147780924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GU!MTB"
        threat_id = "2147780924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {54 89 e6 89 16 c7 46 08 01 00 00 00 c7 46 04 00 00 00 00 8b 15 [0-8] 89 4c 24 ?? ff d2}  //weight: 10, accuracy: Low
        $x_10_2 = "ESTAPPPexe" ascii //weight: 10
        $x_10_3 = "tttt32" ascii //weight: 10
        $x_1_4 = "OutputDebugStringA" ascii //weight: 1
        $x_1_5 = "CreatePointerMoniker" ascii //weight: 1
        $x_1_6 = "Xhot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_GV_2147780925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GV!MTB"
        threat_id = "2147780925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 8b 74 24 ?? c6 06 54 8b 74 24 ?? 89 e7 89 37 c7 47 08 01 00 00 00 c7 47 04 00 00 00 00 8b 35 ?? ?? ?? ?? 89 44 24 ?? 89 4c 24 ?? 89 54 24 ?? ff d6}  //weight: 10, accuracy: Low
        $x_10_2 = "ESTAPPPexe" ascii //weight: 10
        $x_10_3 = "tttt32" ascii //weight: 10
        $x_1_4 = "OutputDebugStringA" ascii //weight: 1
        $x_1_5 = "CreatePointerMoniker" ascii //weight: 1
        $x_1_6 = "Xhot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_PC_2147781118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PC!MTB"
        threat_id = "2147781118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 08 5b 8b e5 5d c3 27 00 8b [0-5] 33 [0-5] c7 05 [0-8] 01 [0-5] a1 [0-4] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EDC_2147781169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EDC!MTB"
        threat_id = "2147781169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {47 ba 29 9a a5 62 f5 4c 4a 2d a0 c4 db 0e fa 03 51 95 8c 48 9a 0f 1f 8f eb 03 33 5c a3 53 f3 cc 7b 3b 2a 19 d9 62 e1 19 6a f9 a0 d8 ef 0e fa 83 d1 95 0b 7c ba 0f 1f c3 eb 37 52 7b 03 33 26 cc}  //weight: 10, accuracy: High
        $x_3_2 = "Rpkder336" ascii //weight: 3
        $x_3_3 = "FGERN.pdb" ascii //weight: 3
        $x_2_4 = "CreatePointerMoniker" ascii //weight: 2
        $x_2_5 = "CreateStreamOnHGlobal" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EVB_2147781170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EVB!MTB"
        threat_id = "2147781170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c4 75 f8 71 bd 6b 49 7e 3f 54 b9 6b 7b ef a4 e6 a2 97 91 63 1a 6d 64 51 01 30 3b 0a 9f 39 c5 60 c4 94 18 11 dd 4c 49 92 73 d3 39 6b 7b ef f0 e5 d5 96 a5 03 ba 6d 18 b1 21 11 4f 8a be d9 79 60}  //weight: 10, accuracy: High
        $x_3_2 = "Rpkder336" ascii //weight: 3
        $x_3_3 = "FGERN.pdb" ascii //weight: 3
        $x_2_4 = "RegOverridePredefKey" ascii //weight: 2
        $x_2_5 = "RasGetConnectionStatistics" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RW_2147781218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RW!MTB"
        threat_id = "2147781218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UnhookWinEvent" ascii //weight: 1
        $x_1_2 = "CryptImportPublicKeyInfo" ascii //weight: 1
        $x_1_3 = "Xiwas" ascii //weight: 1
        $x_1_4 = "ESENT.dll" ascii //weight: 1
        $x_1_5 = "53fromYGthethe" ascii //weight: 1
        $x_1_6 = "ES APP E_" ascii //weight: 1
        $x_1_7 = "elf EX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RW_2147781218_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RW!MTB"
        threat_id = "2147781218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 8c 10 00 00 ff 15 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 04 01 88 02 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d}  //weight: 10, accuracy: Low
        $x_1_2 = "GetSystemInfo" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "GetStartupInfoA" ascii //weight: 1
        $x_1_5 = "ShellExecuteExA" ascii //weight: 1
        $x_1_6 = "MapVirtualKeyA" ascii //weight: 1
        $x_10_7 = "QwtszAcSJAMrTuJxspf3crNTdFNCDqzbOMIlqkB4WG0gygVd" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PD_2147781242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PD!MTB"
        threat_id = "2147781242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "forQYinL" ascii //weight: 1
        $x_1_2 = "firstbycyclej" ascii //weight: 1
        $x_1_3 = "Flash,vandChromecouldI4Feach" ascii //weight: 1
        $x_1_4 = "EChromeBtheB" ascii //weight: 1
        $x_1_5 = "theCbthatB" ascii //weight: 1
        $x_1_6 = "which4Zin" ascii //weight: 1
        $x_1_7 = "XJLTusersd1212" ascii //weight: 1
        $x_1_8 = "ICImageDecompress" ascii //weight: 1
        $x_1_9 = "FGTN|FGT#R65.pdb" ascii //weight: 1
        $x_1_10 = "Oracle Corporation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_KD_2147781340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KD!MTB"
        threat_id = "2147781340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d1 8b c2 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5d}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 08 2b ca 8b 55 08 89 0a 5e 8b e5 5d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_KF_2147781341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KF!MTB"
        threat_id = "2147781341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "thatsites.cofw5ChromemoneyChromep" ascii //weight: 3
        $x_3_2 = "gregorytheHHTML5thethefannouncedfirst" ascii //weight: 3
        $x_3_3 = "53fromYGthethe" ascii //weight: 3
        $x_3_4 = "ES APP E_" ascii //weight: 3
        $x_3_5 = "hootersfor1917UofF8(NPAPI)" ascii //weight: 3
        $x_3_6 = "7155whichexistingtoheatherfeesGearsthemesso" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SN_2147781398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SN!MTB"
        threat_id = "2147781398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FChromezhaskillerFirefoxtoDRumorsis" ascii //weight: 3
        $x_3_2 = "t2theTheIGoogleofaddressWporsche" ascii //weight: 3
        $x_3_3 = "W3and2011,9onjJ2013,2s" ascii //weight: 3
        $x_3_4 = "Hbchickenadsn4yloversThe" ascii //weight: 3
        $x_3_5 = "Rpkder336" ascii //weight: 3
        $x_3_6 = "FgvmFpm.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RM_2147781429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RM!MTB"
        threat_id = "2147781429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 ca 81 c2 01 00 00 00 66 8b 75 8e 66 89 c7 66 31 fe 66 89 75 8e 89 95 44 ff ff ff 8a 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RM_2147781429_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RM!MTB"
        threat_id = "2147781429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c7 38 7a 0c 01 89 ?? ?? ?? ?? ?? 89 [0-7] b2 ?? f6 ea 8a d8 02 1d ?? ?? ?? ?? 83 c5 04 81 fd 79 20 00 00 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RM_2147781429_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RM!MTB"
        threat_id = "2147781429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "researchers,WresultsthelvmuserY" ascii //weight: 1
        $x_1_2 = "due5ptacitgbyRtsig,L" ascii //weight: 1
        $x_1_3 = "7,berchrarks,jGVrrtesting.181strtet.114" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RM_2147781429_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RM!MTB"
        threat_id = "2147781429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9b de 0f ac 8f 0f e9 31 7c 2f 2e c6 99 30 cf d5 60 30 44 69 7a 3a 60 71 27 4d a3 82 4b 0a db d5 7b fd 8f cb 5c 5b e9 51 30 2f ae b2 b8 11 50 09}  //weight: 1, accuracy: High
        $x_1_2 = "LdrGetProcedureA" ascii //weight: 1
        $x_1_3 = "HideCaret" ascii //weight: 1
        $x_1_4 = "ntdll.dl" ascii //weight: 1
        $x_1_5 = "OutputDebugStringA" ascii //weight: 1
        $x_1_6 = "NetConnectionEnum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RM_2147781429_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RM!MTB"
        threat_id = "2147781429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ESENT.dll" ascii //weight: 1
        $x_1_2 = "UnhookWinEvent" ascii //weight: 1
        $x_1_3 = "CryptImportPublicKeyInfo" ascii //weight: 1
        $x_1_4 = "SCardEndTransaction" ascii //weight: 1
        $x_1_5 = "WinSCard.dll" ascii //weight: 1
        $x_1_6 = "CM_Get_Next_Log_Conf" ascii //weight: 1
        $n_50_7 = "bConfigResid8Subtraction" ascii //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RTH_2147781430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RTH!MTB"
        threat_id = "2147781430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nnnvepvmdgh.dll" ascii //weight: 1
        $x_1_2 = "FgvmFpm.pdb" ascii //weight: 1
        $x_1_3 = "Google4FacebookoneNoloadupdatesG" ascii //weight: 1
        $x_1_4 = "9whobroncos8YSXcalled2" ascii //weight: 1
        $x_1_5 = "EChromeBtheB" ascii //weight: 1
        $x_1_6 = "DefineDosDeviceW" ascii //weight: 1
        $x_1_7 = "OutputDebugStringA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PE_2147781485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PE!MTB"
        threat_id = "2147781485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " ES APP E_ " ascii //weight: 1
        $x_1_2 = " elf EX " ascii //weight: 1
        $x_1_3 = "ReadFileEx" ascii //weight: 1
        $x_1_4 = "OutputDebugStringA" ascii //weight: 1
        $x_1_5 = "FindNextUrlCacheGroup" ascii //weight: 1
        $x_1_6 = "FindExecutableW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SB_2147781537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SB!MTB"
        threat_id = "2147781537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "]S_BIS_&" ascii //weight: 3
        $x_3_2 = "RasGetAutodialAddressW" ascii //weight: 3
        $x_3_3 = "FindExecutableW" ascii //weight: 3
        $x_3_4 = "FindNextUrlCacheGroup" ascii //weight: 3
        $x_3_5 = "ShowOwnedPopups" ascii //weight: 3
        $x_3_6 = "StartServiceCtrlDispatcherA" ascii //weight: 3
        $x_3_7 = "ReadFileEx" ascii //weight: 3
        $x_3_8 = "TerminateJobObject" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SE_2147781539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SE!MTB"
        threat_id = "2147781539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SetUrlCacheEntryInfoW" ascii //weight: 3
        $x_3_2 = "ES APP E_" ascii //weight: 3
        $x_3_3 = "elf EX" ascii //weight: 3
        $x_3_4 = "MapVirtualKeyA" ascii //weight: 3
        $x_3_5 = "LoadKeyboardLayoutA" ascii //weight: 3
        $x_3_6 = "SwitchToThisWindow" ascii //weight: 3
        $x_3_7 = "SCardDisconnect" ascii //weight: 3
        $x_3_8 = "SetupDiDeleteDeviceInterfaceData" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ALD_2147781619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ALD!MTB"
        threat_id = "2147781619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LdrGetProcedureA" ascii //weight: 3
        $x_3_2 = "Rpkder336" ascii //weight: 3
        $x_3_3 = "FGTN|FGT#R65.pdb" ascii //weight: 3
        $x_3_4 = "W3and2011,9onjJ2013,2s" ascii //weight: 3
        $x_3_5 = "enabledhunlikebostonfq43phoenix" ascii //weight: 3
        $x_3_6 = "Google4FacebookoneNoloadupdatesG" ascii //weight: 3
        $x_3_7 = "9whobroncos8YSXcalled2" ascii //weight: 3
        $x_3_8 = "Lthreshold.39sagainstofUbutGUthe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AF_2147781681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AF!MTB"
        threat_id = "2147781681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b cf 0f af ce 8b c6 99 2b c2 8b 55 fc d1 f8 03 c8 8b 45 08 8a 04 02 2b cb 32 c1}  //weight: 10, accuracy: High
        $x_10_2 = {33 c4 89 84 24 70 10 00 00 8b 45 08 53 56 33 db 57 33 ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AK_2147781683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AK!MTB"
        threat_id = "2147781683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 0c 8d 34 3a 03 c6 8b d6 8d 04 45 90 ca ff ff 0f b7 c0 89 44 24 0c 8a 4c 24 0c 2a ca 8b 54 24 10 83 44 24 10 04 80 e9 02 8b 02 05 3c 17 0d 01 89 02 66 8b 54 24 0c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AK_2147781683_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AK!MTB"
        threat_id = "2147781683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 44 24 33 f4 8b 44 24 1c c6 44 24 33 36 66 8b 4c 24 0e 66 0f af c9 8a 50 01 66 89 4c 24 42 0f b6 c2 66 c7 44 24 42 77 c7 83 f8 25 0f 84 d0 fe ff ff e9 74 fe ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AK_2147781683_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AK!MTB"
        threat_id = "2147781683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b ca 83 c0 21 03 c8 53 55 56 8b 35 ?? ?? ?? ?? 2b d1 69 c1 04 67 01 00 83 c6 21 03 f2}  //weight: 10, accuracy: Low
        $x_10_2 = {3b c8 74 15 28 8a ?? ?? ?? ?? 8d 04 4d 04 00 00 00 41 a3 ?? ?? ?? ?? 03 c8 4a 83 fa 01 7f da}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AK_2147781683_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AK!MTB"
        threat_id = "2147781683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c1 f8 89 74 24 14 03 ca 8d 04 4d 06 00 00 00 89 44 24 18 8b 7c 24 1c 8d 50 46 03 d1 8b f2}  //weight: 10, accuracy: High
        $x_10_2 = {8b 07 05 cc 10 06 01 89 07 83 c7 04 89 7c 24 1c 33 ff 2b d3 a3 ?? ?? ?? ?? 1b ff 2b 54 24 18 1b 7c 24 14}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_LAD_2147781706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.LAD!MTB"
        threat_id = "2147781706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d3 c0 8a fc 8a e6 d3 cb ff 4d ?? 75 ?? 89 55 ?? 2b 55 ?? 09 da 83 e0 ?? 09 d0 8b 55 ?? 59 aa 49 75}  //weight: 10, accuracy: Low
        $x_10_2 = {d3 c0 8a fc 8a e6 d3 cb ff 4d ?? 75 ?? 57 83 e7 00 31 df 83 e0 00 09 f8 5f 59 aa 49 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_LBL_2147781751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.LBL!MTB"
        threat_id = "2147781751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d3 c0 8a fc 8a e6 d3 cb ff 4d ?? 75 ?? 89 4d ?? 2b 4d ?? 31 d9 83 e0 00 09 c8 8b 4d ?? 81 e1 [0-4] 8b 0c e4 83 ec ?? aa 49 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_LBN_2147781773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.LBN!MTB"
        threat_id = "2147781773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d3 c0 8a fc 8a e6 d3 cb ff 4d ?? 75 f3 89 75 ?? 33 75 ?? 09 de 83 e0 00 09 f0 8b 75 ?? 8f 45 ?? 8b 4d ?? aa 49 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PF_2147781782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PF!MTB"
        threat_id = "2147781782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 83 [0-2] 89 [0-2] 81 [0-6] 0f [0-5] 0f [0-6] 8b [0-5] 8d [0-3] 89 [0-5] a1 [0-4] 03 [0-2] 8b [0-5] 89 [0-5] 69 [0-9] 0f [0-3] 03 ?? 66 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PG_2147781792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PG!MTB"
        threat_id = "2147781792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b c1 74 19 0f [0-6] 8b c3 00 9a [0-4] 2b c1 83 [0-2] a3 [0-4] 83 [0-2] 83 [0-2] 7f ?? 85 f6 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PH_2147781820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PH!MTB"
        threat_id = "2147781820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 c0 8a fc 8a e6 d3 ?? ff [0-4] 6a 00 89 [0-2] 29 ?? 09 ?? 89 ?? 5d 81 ?? ?? ?? ?? ?? 8f ?? ?? 03 ?? ?? aa 49 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 c0 8a fc 8a e6 d3 cb ff [0-4] 89 [0-2] 33 [0-4] 83 [0-4] 8b [0-2] 8f [0-2] 8b [0-2] aa 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_PI_2147782043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PI!MTB"
        threat_id = "2147782043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 51 4e 62 0b fd c4 90 c3 35 a5 6b ce cf 49 42 2d 8a 18 9b e6 fe 67 d8 d3 61 d0 34 c9 8d be 4f 1e 84 6d e1 8a fe c4 a4 c3 16 86 9e 01 cf 49 41}  //weight: 1, accuracy: High
        $x_1_2 = "HBITMAP_UserSize" ascii //weight: 1
        $x_1_3 = "PolylineTo" ascii //weight: 1
        $x_1_4 = "FindCloseUrlCache" ascii //weight: 1
        $x_1_5 = "SwitchToThisWindow" ascii //weight: 1
        $x_1_6 = "LoadKeyboardLayoutA" ascii //weight: 1
        $x_1_7 = "OpenSemaphoreW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AFX_2147782139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AFX!MTB"
        threat_id = "2147782139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 c3 3b f8 74 14 66 29 11 8b c2 66 8b 1d ?? ?? ?? ?? 2b c7 83 e8 4e 0f b7 f0 83 e9 02 81 f9 ?? ?? ?? ?? 7f da}  //weight: 10, accuracy: Low
        $x_10_2 = {2a c2 2c 4e 0f b6 c0 2b c2 8b 54 24 10 2b c1 8d 4b 04 02 c8 57 8d 7b 5c 88 4c 24 13}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_VT_2147782356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.VT!MTB"
        threat_id = "2147782356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Rpkder336" ascii //weight: 3
        $x_3_2 = "kernel32.Sleep" ascii //weight: 3
        $x_3_3 = "fpn.pdb" ascii //weight: 3
        $x_3_4 = "744siteslW3C," ascii //weight: 3
        $x_3_5 = "Adblockfeaturesf36%u4BKA" ascii //weight: 3
        $x_3_6 = ",system.192E666666processesZsecurity" ascii //weight: 3
        $x_3_7 = "w2jconnecteddwithw3,once" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_VD_2147782406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.VD!MTB"
        threat_id = "2147782406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AcquireSRWLockExclusive" ascii //weight: 3
        $x_3_2 = "TryAcquireSRWLockExclusive" ascii //weight: 3
        $x_3_3 = "ReleaseSRWLockExclusive" ascii //weight: 3
        $x_3_4 = "From\\Famous\\why\\together.pdb" ascii //weight: 3
        $x_3_5 = "Appearlet" ascii //weight: 3
        $x_3_6 = "Haslot" ascii //weight: 3
        $x_3_7 = "IsProcessorFeaturePresent" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BKY_2147782653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BKY!MTB"
        threat_id = "2147782653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 83 05 ?? ?? ?? ?? ?? 83 05 ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 24 00 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SBB_2147782785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SBB!MTB"
        threat_id = "2147782785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "success.pdb" ascii //weight: 3
        $x_3_2 = "IsProcessorFeaturePresent" ascii //weight: 3
        $x_3_3 = "pppp1111ffff" ascii //weight: 3
        $x_3_4 = "WriteConsoleW" ascii //weight: 3
        $x_3_5 = "FlushFileBuffers" ascii //weight: 3
        $x_3_6 = "DllRegisterServer" ascii //weight: 3
        $x_3_7 = "PostMessageA" ascii //weight: 3
        $x_3_8 = "CallNextHookEx" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SBB_2147782785_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SBB!MTB"
        threat_id = "2147782785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "fpn.pdb" ascii //weight: 3
        $x_3_2 = "DeleteSecurityContext" ascii //weight: 3
        $x_3_3 = "kernel32.Sleep" ascii //weight: 3
        $x_3_4 = "RegOverridePredefKey" ascii //weight: 3
        $x_3_5 = ",system.192E666666processesZsecurity" ascii //weight: 3
        $x_3_6 = "w2jconnecteddwithw3,once" ascii //weight: 3
        $x_3_7 = "mdecoding.150slayerkwith4on1" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_WF_2147782914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.WF!MTB"
        threat_id = "2147782914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DTTYUNMP.pdb" ascii //weight: 3
        $x_3_2 = "NdrClearOutParameters" ascii //weight: 3
        $x_3_3 = "raisingn587" ascii //weight: 3
        $x_3_4 = "aincluding1p" ascii //weight: 3
        $x_3_5 = "SetICMMode" ascii //weight: 3
        $x_3_6 = "RPCRT4.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GB_2147783930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GB!MTB"
        threat_id = "2147783930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 32 00 cc [0-4] cc [0-4] cc}  //weight: 10, accuracy: Low
        $x_2_2 = "llosewwq.ll" ascii //weight: 2
        $x_2_3 = ".pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_GB_2147783930_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GB!MTB"
        threat_id = "2147783930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 74 24 0c 89 4c 24 08 89 54 24 04 8d 65 f4}  //weight: 1, accuracy: High
        $x_10_2 = {cc cc 40 cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3}  //weight: 10, accuracy: Low
        $x_10_3 = "tttt32" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GB_2147783930_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GB!MTB"
        threat_id = "2147783930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 23 00 cc cc}  //weight: 10, accuracy: Low
        $x_5_2 = "llosewwq.ll" ascii //weight: 5
        $x_5_3 = {0f b6 f8 29 fb 88 65 ?? 88 d8 88 45 ?? 8b 7d ?? 8a 45 ?? 8b 5d ?? c6 45 ?? ?? 88 04 1f 89 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_GB_2147783930_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GB!MTB"
        threat_id = "2147783930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6f c6 44 24 ?? 63 c6 44 24 ?? 00 8a 84 24 ?? 00 00 00 88 84 24 ?? 00 00 00 c6 84 24 ?? 00 00 00 58 89 54 24 ?? e8 ?? ?? ?? ?? 8b 54 24 ?? 66 8b 5c 24 ?? 66 89 9c 24 ?? 00 00 00 89 04 24 89 54 24 ?? e8}  //weight: 10, accuracy: Low
        $x_10_2 = {72 c6 44 24 ?? 6e 8a 74 24 ?? 80 f6 ?? 88 b4 24 ?? 00 00 00 80 f1 ?? 88 54 24 ?? c6 44 24 ?? 6c 66 8b 74 24 1c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_PU_2147783937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.PU!MTB"
        threat_id = "2147783937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DExrlorerincludedGrogleWE" ascii //weight: 1
        $x_1_2 = "thatPnew" ascii //weight: 1
        $x_1_3 = "iallowslater" ascii //weight: 1
        $x_1_4 = "fortoFothrrdFlashshare" ascii //weight: 1
        $x_1_5 = "Adblockfeaturesf36%u4BKA" ascii //weight: 1
        $x_1_6 = "browserunderFebruarymtestb" ascii //weight: 1
        $x_1_7 = "BEconomicmodetypes" ascii //weight: 1
        $x_1_8 = "markGoogleZlogsa" ascii //weight: 1
        $x_1_9 = "Chromecorelease" ascii //weight: 1
        $x_1_10 = "AddUsersToEncryptedFile" ascii //weight: 1
        $x_10_11 = {21 c0 8b 4d ?? 8b [0-6] 89 [0-6] 8a [0-2] 0f [0-7] 29 ?? 8b [0-3] 89 [0-2] 89 [0-3] e8 [0-4] 8b [0-3] 01 ?? 88 [0-8] 8b [0-2] 8a [0-6] 8b [0-6] 88}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_AX_2147784028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AX!MTB"
        threat_id = "2147784028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff ff b8 08 00 00 00 c1 e0 02 89 45 fc 8b 4d fc 81 b9 ?? ?? ?? ?? 1e 04 00 00 75 25 8b 55 fc 83 ba 34 c0 12 01 00 75 19 b8 08 00 00 00 d1 e0 8b 0d ?? ?? ?? ?? 03 88}  //weight: 10, accuracy: Low
        $x_3_2 = "Sellhour" ascii //weight: 3
        $x_3_3 = "Surprisemost" ascii //weight: 3
        $x_3_4 = "GetAsyncKeyState" ascii //weight: 3
        $x_3_5 = "137-little" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DD_2147784099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DD!MTB"
        threat_id = "2147784099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DoorrledFgppr" ascii //weight: 3
        $x_3_2 = "Gpernfedeefe.pdb" ascii //weight: 3
        $x_3_3 = "Self ex" ascii //weight: 3
        $x_3_4 = "MprInfoBlockRemove" ascii //weight: 3
        $x_3_5 = "testapp.exe" ascii //weight: 3
        $x_3_6 = "JetSeek" ascii //weight: 3
        $x_3_7 = "GetTempFileNameA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DD_2147784099_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DD!MTB"
        threat_id = "2147784099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 16 01 d1 8b 55 ?? 81 ea ?? ?? ?? ?? 89 c8 89 55 ?? 99 8b 4d ?? f7 f9 8b 75 ?? 89 16 8b 55 ?? 8b 0a 8b 55 ?? 8b 12 0f b6 0c 0a 8b 16 8b 75 ?? 8b 36 0f b6 14 16 31 d1 8b 55 ?? 8b 32 8b 55 c4 8b 12 88 0c 32}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 14 16 8b 75 ?? 8b 7d ?? 0f b6 34 37 01 f2 89 d0 99 f7 f9 89 55 ?? 8b 55 ?? 8b 75 ?? 0f b6 14 16 8b 75 ?? 8b 7d ?? 0f b6 34 37 31 f2 88 d3 8b 55 ?? 8b 75 ?? 88 1c 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_DD_2147784099_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DD!MTB"
        threat_id = "2147784099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 a9 00 00 00 8b 4d ?? 66 89 01 8b 55 ?? 0f b7 02 83 e8 40 8b 4d ?? 66 89 01 ba ae 00 00 00 8b 45 ?? 66 89 50 02 8b 4d ?? 0f b7 51 02 83 ea 40 8b 45 ?? 66 89 50 02 b9 b4 00 00 00 8b 55 ?? 66 89 4a 04 8b 45 ?? 0f b7 48 04 83 e9 40 8b 55 ?? 66 89 4a 04 b8 a5 00 00 00 8b 4d ?? 66 89 41 06 8b 55 ?? 0f b7 42 06 83 e8 40 8b 4d ?? 66 89 41 06 ba b2 00 00 00 8b 45 ?? 66 89 50 08 8b 4d ?? 0f b7 51 08 83 ea 40 8b 45 ?? 66 89 50 08 b9 a6 00 00 00 8b 55 ?? 66 89 4a 0a 8b 45 ?? 0f b7 48 0a 83 e9 40 8b 55 ?? 66 89 4a 0a b8 a1 00 00 00 8b 4d ?? 66 89 41 0c 8b 55 ?? 0f b7 42 0c 83 e8 40 8b 4d ?? 66 89 41 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ea 40 8b 45 ?? 66 89 50 4a b9 a1 00 00 00 8b 55 ?? 66 89 4a 4c 8b 45 ?? 0f b7 48 4c 83 e9 40 8b 55 ?? 66 89 4a 4c b8 70 00 00 00 8b 4d ?? 66 89 41 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DL_2147785224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DL!MTB"
        threat_id = "2147785224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "GrrppdemmrFppe" ascii //weight: 3
        $x_3_2 = "Grpppmde.pdb" ascii //weight: 3
        $x_3_3 = "Self ex" ascii //weight: 3
        $x_3_4 = "MprInfoBlockRemove" ascii //weight: 3
        $x_3_5 = "InternetCrackUrlA" ascii //weight: 3
        $x_3_6 = "WritePrivateProfileStructW" ascii //weight: 3
        $x_3_7 = "GetTempFileNameA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AY_2147786454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AY!MTB"
        threat_id = "2147786454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "333szAcSJAMrTuJxspf3crNTdFNCDqzbOMIlqkB4WG0gygVd" ascii //weight: 3
        $x_3_2 = "PxCpyI64" ascii //weight: 3
        $x_3_3 = "ImmDisableIME" ascii //weight: 3
        $x_3_4 = "DeleteEnhMetaFile" ascii //weight: 3
        $x_3_5 = "GetThreadDesktop" ascii //weight: 3
        $x_3_6 = "GetStockObject" ascii //weight: 3
        $x_3_7 = "IsCharAlphaNumericA" ascii //weight: 3
        $x_3_8 = "tttta8" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DM_2147786461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DM!MTB"
        threat_id = "2147786461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 b9 ca b1 66 8b 54 24 28 66 29 d1 66 89 4c 24 6a 0f b6 00 3d b8}  //weight: 10, accuracy: High
        $x_3_2 = "FFPGGLBM.pdb" ascii //weight: 3
        $x_3_3 = "AddJobW" ascii //weight: 3
        $x_3_4 = "SHEnumerateUnreadMailAccountsW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DM_2147786461_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DM!MTB"
        threat_id = "2147786461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b9 f0 02 00 00 31 d2 f7 f1 89 85 0c fd ff ff 31 ff 3b bd 0c fd ff ff 73 3c 69 c7 f0 02 00 00 ff 75 2c 8d 94 06 70 02}  //weight: 10, accuracy: High
        $x_3_2 = "Heh*.bihile" ascii //weight: 3
        $x_3_3 = "hIZE_hTHORhO_AUhLE_ThUNABhE" ascii //weight: 3
        $x_3_4 = "gethostbyname" ascii //weight: 3
        $x_3_5 = "WSASocketA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_DV_2147786530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DV!MTB"
        threat_id = "2147786530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "tttt32" ascii //weight: 3
        $x_3_2 = "rrpokdmgnn" ascii //weight: 3
        $x_3_3 = "FnloderTrRppee" ascii //weight: 3
        $x_3_4 = "kernel32.Sleep" ascii //weight: 3
        $x_3_5 = "Dpperse.pdb" ascii //weight: 3
        $x_3_6 = "744siteslW3C," ascii //weight: 3
        $x_3_7 = "Adblockfeaturesf36%u4BKA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DN_2147786659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DN!MTB"
        threat_id = "2147786659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 00 90 48 8d 4b 18 48 83 c4 30 5b 48 ff}  //weight: 10, accuracy: High
        $x_10_2 = {8b c6 c1 e0 06 2b c6 b9 ff ff 00 00 2b c8 83 3d ?? ?? ?? ?? 05 57 0f b7 c1 77 15}  //weight: 10, accuracy: Low
        $x_3_3 = "Eithernothing" ascii //weight: 3
        $x_3_4 = "Smileschool" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RF_2147786742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RF!MTB"
        threat_id = "2147786742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GoogleThe3Ond5DHsmall" ascii //weight: 1
        $x_1_2 = "B5AV8nlaunchedhelpmecrWindows" ascii //weight: 1
        $x_1_3 = "kpYrthistaZbefores" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GE_2147786952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GE!MTB"
        threat_id = "2147786952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c3 2b 05 ?? ?? ?? ?? 81 c7 2c 3d 05 01 05 ?? ?? ?? ?? 80 c2 ?? 66 a3 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 bc 2e ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 02 d2 02 d1 02 15 ?? ?? ?? ?? 83 c6 04 81 fe 50 27 00 00 88 54 24 ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GE_2147786952_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GE!MTB"
        threat_id = "2147786952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b d8 8b fe 83 c9 ff 33 c0 83 c4 04 f2 ae f7 d1 2b f9 8b d1 8b f7 8b fb c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 33 f6 85 ed 76 20}  //weight: 10, accuracy: High
        $x_1_2 = "http://FileApi.gyaott.top/001/puppet.Txt" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GE_2147786952_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GE!MTB"
        threat_id = "2147786952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c3 88 d8 88 45 ?? 8b 5d ?? 8b 45 ?? 89 45 ?? 8a 45 ?? 8b 7d ?? 88 04 3b 89 75 ?? 89 4d ?? 89 55 ?? 83 c4}  //weight: 1, accuracy: Low
        $x_1_2 = {66 8b 54 24 04 66 81 c2 32 7b 66 89 54 24 ?? 8a 5c 24 ?? 88 1c 01 8d 65 f4 5f 5e}  //weight: 1, accuracy: Low
        $x_5_3 = {40 cc cc cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3}  //weight: 5, accuracy: Low
        $x_5_4 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 23 00 cc cc cc 40 eb}  //weight: 5, accuracy: Low
        $x_10_5 = "tttt32" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_GF_2147786953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GF!MTB"
        threat_id = "2147786953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 c7 d4 e0 08 01 89 3d ?? ?? ?? ?? 89 bc 2e ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 66 8b 0d ?? ?? ?? ?? 8a c2 02 c1 83 c6 04 2c ?? 81 fe 33 1c 00 00 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GF_2147786953_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GF!MTB"
        threat_id = "2147786953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 54 24 0c 05 c8 50 04 01 83 44 24 ?? 04 a3 ?? ?? ?? ?? 89 02 8b 15 ?? ?? ?? ?? 2b 54 24 ?? 8b 44 24 ?? 81 c2 14 82 01 00 83 6c 24 ?? 01 89 15 ?? ?? ?? ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GF_2147786953_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GF!MTB"
        threat_id = "2147786953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 14 24 89 44 24 ?? c7 44 24 ?? ?? ?? ?? ?? 89 74 24 ?? 89 4c 24 ?? e8}  //weight: 1, accuracy: Low
        $x_5_2 = {40 cc cc cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3}  //weight: 5, accuracy: Low
        $x_5_3 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 23 00 cc cc cc 40 eb}  //weight: 5, accuracy: Low
        $x_10_4 = "tttt32" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dridex_GF_2147786953_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GF!MTB"
        threat_id = "2147786953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 8b b4 24 ?? ?? ?? ?? 66 03 b4 24 ?? ?? ?? ?? 66 89 b4 24 ?? ?? ?? ?? c6 44 24 ?? 00 c6 44 24 ?? ?? 8b 4c 24 ?? 89 8c 24 ?? ?? ?? ?? 89 44 24 ?? e8 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 89 04 24 89 4c 24 04 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {65 c6 84 24 ?? ?? ?? ?? 83 c6 84 24 ?? ?? ?? ?? 6c c6 84 24 ?? ?? ?? ?? 33 c6 84 24 ?? ?? ?? ?? 32 c6 84 24 ?? ?? ?? ?? 2e 66 8b 94 24 ?? ?? ?? ?? c6 84 24 ?? ?? ?? ?? 64 c6 84 24 ?? ?? ?? ?? 6c c6 84 24 ?? ?? ?? ?? 6c c6 84 24 ?? ?? ?? ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DH_2147787013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DH!MTB"
        threat_id = "2147787013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "tttt32" ascii //weight: 3
        $x_3_2 = "rrpokdmgnn" ascii //weight: 3
        $x_3_3 = "FnloderTrRppee" ascii //weight: 3
        $x_3_4 = "RRGTYY.pdb" ascii //weight: 3
        $x_3_5 = "rconstituency.5Tabvafterprotocol11,any2112" ascii //weight: 3
        $x_3_6 = "VoPolicy.189andtoRuraasdfgh" ascii //weight: 3
        $x_3_7 = "the1gtheyfunctionsasd" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SD_2147787510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SD!MTB"
        threat_id = "2147787510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 50 03 03 d3 8a c2 2a c1 b1 47 2a 44 24 07 f6 e9 2a c2 02 44 24 0c 0f b6 d0}  //weight: 10, accuracy: High
        $x_10_2 = {81 c1 e0 d0 ff ff 53 8b 5c 24 08 03 cb 8b c1 80 c1 57 2b c2 02 cb 56 57}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SCD_2147787512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SCD!MTB"
        threat_id = "2147787512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "elf EX" ascii //weight: 3
        $x_3_2 = "ES APP E_" ascii //weight: 3
        $x_3_3 = "FindExecutableW" ascii //weight: 3
        $x_3_4 = "FindNextUrlCacheGroup" ascii //weight: 3
        $x_3_5 = "ShowOwnedPopups" ascii //weight: 3
        $x_3_6 = "StartServiceCtrlDispatcherA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ACD_2147787529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ACD!MTB"
        threat_id = "2147787529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4c 8b d9 0f b6 d2 49 b9 01 01 01 01 01 01 01 01 4c 0f af ca 49 83 f8 10 0f 86 f2 00 00 00 66 49 0f 6e c1 66 0f 60 c0 49 81 f8 80 00 00 00 77 10 0f ba 25 e8 bb 04 00 02}  //weight: 10, accuracy: High
        $x_3_2 = "WaitForThreadpoolTimerCallbacks" ascii //weight: 3
        $x_3_3 = "FlushProcessWriteBuffers" ascii //weight: 3
        $x_3_4 = "AcquireSRWLockExclusive" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BAN_2147787592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BAN!MTB"
        threat_id = "2147787592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FnloderTrRppee" ascii //weight: 3
        $x_3_2 = "yyseew4.pdb" ascii //weight: 3
        $x_3_3 = "rrpokdmgnn" ascii //weight: 3
        $x_3_4 = "tEfreeKvirtualwhichChrome" ascii //weight: 3
        $x_3_5 = "RegOverridePredefKey" ascii //weight: 3
        $x_3_6 = "kernel32.Sleep" ascii //weight: 3
        $x_3_7 = "chosen9Fpart" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BAM_2147787695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BAM!MTB"
        threat_id = "2147787695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FWroeeWqoinnmw" ascii //weight: 3
        $x_3_2 = "kernel32.Sleep" ascii //weight: 3
        $x_3_3 = "FTTUUOP.pdb" ascii //weight: 3
        $x_3_4 = "RegOverridePredefKey" ascii //weight: 3
        $x_3_5 = "been2exploitsused" ascii //weight: 3
        $x_3_6 = "LinuxweekKInternet3NPAPIitForChrome" ascii //weight: 3
        $x_3_7 = "APP.EXE" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AMH_2147787871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AMH!MTB"
        threat_id = "2147787871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c4 fd 14 e0 64 da 32 01 f9 51 16 72 d6 8d f9 aa 29 23 9f cd e8 64 36 8e 19 f6 6f fb bd 5a 62 0b}  //weight: 10, accuracy: High
        $x_3_2 = "UrlUnescapeW" ascii //weight: 3
        $x_3_3 = "MprAdminInterfaceTransportAdd" ascii //weight: 3
        $x_3_4 = "GetUrlCacheEntryInfoW" ascii //weight: 3
        $x_3_5 = "CryptCATPutAttrInfo" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AHB_2147788190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AHB!MTB"
        threat_id = "2147788190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "WEQSDE|T.pdb" ascii //weight: 3
        $x_3_2 = "kernel32.Sleep" ascii //weight: 3
        $x_3_3 = "D41interruptLeaked6Jf" ascii //weight: 3
        $x_3_4 = "Chromensubmenu76Store164emanage" ascii //weight: 3
        $x_3_5 = "backovdefault2" ascii //weight: 3
        $x_3_6 = "qcmLallXHexceptsallows" ascii //weight: 3
        $x_3_7 = "Ve1teensMessenger172thex" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ABM_2147789166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ABM!MTB"
        threat_id = "2147789166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "gfkuaithpt" ascii //weight: 3
        $x_3_2 = "rs-l6Z" ascii //weight: 3
        $x_3_3 = "TryAcquireSRWLockExclusive" ascii //weight: 3
        $x_3_4 = "ReleaseSRWLockExclusive" ascii //weight: 3
        $x_3_5 = "service.dll" ascii //weight: 3
        $x_3_6 = "ServiceMain" ascii //weight: 3
        $x_3_7 = "Fp:pyFx2" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AS_2147789249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AS!MTB"
        threat_id = "2147789249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 2b 94 24 9e 00 00 00 88 cf 08 fb 88 9c 24 d6 00 00 00 66 89 94 24 9e}  //weight: 10, accuracy: High
        $x_10_2 = {8a 84 24 d6 00 00 00 f6 d8 8b 8c 24 e0 00 00 00 88 84 24 d6 00 00 00 8a 84 24 d7 00 00 00 f6 d8 88 84 24 d6}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AGC_2147789470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AGC!MTB"
        threat_id = "2147789470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 5c 24 33 89 44 24 2c 88 d8 f6 e3 88 84 24 b3 00 00 00 8b 74 24 2c 31 f1 89 8c 24 98}  //weight: 10, accuracy: High
        $x_10_2 = {c0 88 84 24 b3 00 00 00 b0 74 8a 4c 24 33 28 c8 8b 54 24 48 8b 74 24 5c 88 84 24 b3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AT_2147789478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AT!MTB"
        threat_id = "2147789478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FFPGGLBM.pdb" ascii //weight: 3
        $x_3_2 = "hReachappear.1529ChromiumFacebook," ascii //weight: 3
        $x_3_3 = "SHEnumerateUnreadMailAccountsW" ascii //weight: 3
        $x_3_4 = "AttachThreadInput" ascii //weight: 3
        $x_3_5 = "QueryUsersOnEncryptedFile" ascii //weight: 3
        $x_3_6 = "ScrollConsoleScreenBufferA" ascii //weight: 3
        $x_3_7 = "p25menu,quicker,Gwilliesitesdexterand" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AM_2147792906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AM!MTB"
        threat_id = "2147792906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 44 24 14 04 8d 0c 40 2b 4c 24 18 ff 4c 24 24 0f b7 d1 8a 4c 24 0c}  //weight: 10, accuracy: High
        $x_10_2 = {8b c8 2b ce 2b cb 8b f1 0f b7 ca 03 cf}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AM_2147792906_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AM!MTB"
        threat_id = "2147792906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4c 24 20 01 c1 88 cb 88 5c 24 5f 8a 5c 24 5f 8b 84 24 f0 00 00 00 8b 4d 08 88 1c 01}  //weight: 10, accuracy: High
        $x_10_2 = {8b 45 10 8b 8c 24 04 01 00 00 8a 94 24 0f 01 00 00 32 94 24 0f 01 00 00 88 94 24 0f 01 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AM_2147792906_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AM!MTB"
        threat_id = "2147792906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b c1 89 45 f4 8b 55 fc 8b 45 f0 8a 08 88 0a 8b 55 fc}  //weight: 10, accuracy: High
        $x_10_2 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 09 8b 44 24 04 f7 e1 c2 10 00 53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b c2 10 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AM_2147792906_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AM!MTB"
        threat_id = "2147792906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 44 24 6f 88 c1 80 c1 9d 88 4c 24 4f 88 c1 80 f1 e3 88 4c 24 55}  //weight: 10, accuracy: High
        $x_10_2 = {88 44 24 33 89 d0 89 54 24 2c f7 e7 69 fe 6e c6 03 7a 01 fa 89 44 24 60 89 54 24 64 0f b6 c1 83 f8 6a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AM_2147792906_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AM!MTB"
        threat_id = "2147792906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "tokenythesPepper" ascii //weight: 3
        $x_3_2 = "application.vNvstevereturn.theE" ascii //weight: 3
        $x_3_3 = "rpidebbfll.pdb" ascii //weight: 3
        $x_3_4 = "gpoiree" ascii //weight: 3
        $x_3_5 = "SHGetDesktopFolder" ascii //weight: 3
        $x_3_6 = "DDplsoecrVwqase" ascii //weight: 3
        $x_3_7 = "RegLoadAppKeyA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AM_2147792906_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AM!MTB"
        threat_id = "2147792906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Design8server.114OOctoberPNb" ascii //weight: 3
        $x_3_2 = "bostonkeptPversions;ThePPAPInJ2" ascii //weight: 3
        $x_3_3 = "LosskiwFpponf" ascii //weight: 3
        $x_3_4 = "ffgtbywq.pdb" ascii //weight: 3
        $x_3_5 = "CryptSIPCreateIndirectData" ascii //weight: 3
        $x_3_6 = "RasDeleteEntryW" ascii //weight: 3
        $x_3_7 = "kernel32.Sleep" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AKN_2147793149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AKN!MTB"
        threat_id = "2147793149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b c1 2d 75 6a 00 00 0f b7 c0 8d b8 db 3b 01 00 03 fe 83}  //weight: 10, accuracy: High
        $x_3_2 = "Huntroom" ascii //weight: 3
        $x_3_3 = "Insectgot" ascii //weight: 3
        $x_3_4 = "Pushstretch" ascii //weight: 3
        $x_3_5 = "Redsyllable" ascii //weight: 3
        $x_3_6 = "Quart\\table.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AKM_2147793151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AKM!MTB"
        threat_id = "2147793151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "PloaesRvommnr" ascii //weight: 3
        $x_3_2 = "kernel32.Sleep" ascii //weight: 3
        $x_3_3 = "mYAPP.EXE" ascii //weight: 3
        $x_3_4 = "Chromensubmenu76Store164emanage" ascii //weight: 3
        $x_3_5 = "patVersionsaidtester" ascii //weight: 3
        $x_3_6 = "JetEndSession" ascii //weight: 3
        $x_3_7 = "CryptSIPCreateIndirectData" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ES_2147793152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ES!MTB"
        threat_id = "2147793152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 ca 8b 45 f0 6b c0 38 99 be 38 00 00 00 f7 fe 88 8c 05 f8 e1 ff ff 8b 45 f0 33 c9 8a 8c 05 f8 e1 ff ff 83 f9 05}  //weight: 10, accuracy: High
        $x_10_2 = {8a 84 15 f8 e1 ff ff 83 e8 01 8b 4d f0 88 84 0d f8 e1 ff ff 8b 55 f0 83 c2 01 89 55 f0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ES_2147793152_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ES!MTB"
        threat_id = "2147793152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5b 3b 33 82 92 73 e9 64 96 e7 49 5f 0d 43 b7 7c c5 f1 82 ec 73 7b 53 11 3d dc 53 3b e2 1e e3 06 a8 90 58 af 44 b4 91 df 31 39 8a d2 46 15 35 1b}  //weight: 5, accuracy: High
        $x_5_2 = {4c 1d af 38 79 87 0b f7 58 b4 be 0e 37 de fd 54}  //weight: 5, accuracy: High
        $x_1_3 = "LdrGetProcedureA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EM_2147793869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EM!MTB"
        threat_id = "2147793869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 08 0f b6 c1 83 f8 6a 89 44 24 1c}  //weight: 10, accuracy: High
        $x_10_2 = {8a 08 8b 44 24 50 25 0c 69 3a 7d 89 44 24 50 c7 44 24 54 00 00 00 00 0f b6 c1 3d b8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EM_2147793869_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EM!MTB"
        threat_id = "2147793869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 0c 38 8d 7f 01 4e 88 4f ff 8b c2 2b c6 2d 26 2c 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {02 c0 8d 8e 79 d3 ff ff 2a c4 02 c3 66 03 d9 8b 0c 2f 02 c0 81 c1 68 9c 02 01 66}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EM_2147793869_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EM!MTB"
        threat_id = "2147793869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4c 24 1c 89 4c 24 48 8b 54 24 20 89 54 24 4c 66 8b 74 24 56 66 83 f6 ff 8a 18 66 89 74 24 56 0f b6 c3 8b 7c 24 5c}  //weight: 10, accuracy: High
        $x_10_2 = {66 8b 4c 24 56 66 8b 54 24 56 2b 44 24 5c 66 09 d1 66 89 4c 24 56 c7 44 24 2c 5d 09 00 00 89 44 24 18}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EM_2147793869_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EM!MTB"
        threat_id = "2147793869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "GetIfTable" ascii //weight: 3
        $x_3_2 = "RegOverridePredefKey" ascii //weight: 3
        $x_3_3 = "ldollirefgt" ascii //weight: 3
        $x_3_4 = "gpoiree" ascii //weight: 3
        $x_3_5 = "DDplsoecrVwqase" ascii //weight: 3
        $x_3_6 = "kernel32.Sleep" ascii //weight: 3
        $x_3_7 = "rpidebbfll.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EM_2147793869_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EM!MTB"
        threat_id = "2147793869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ucalledManmovedaftervoidbring" ascii //weight: 1
        $x_1_2 = "vlmgus" ascii //weight: 1
        $x_1_3 = "zfromrtheirB" ascii //weight: 1
        $x_1_4 = "shallafterosixthYlightset" ascii //weight: 1
        $x_1_5 = "ieveningreplenishalsoP6ofEmultiply" ascii //weight: 1
        $x_1_6 = "faceNightof,j" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EM_2147793869_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EM!MTB"
        threat_id = "2147793869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "itfirst555eSecurityeitherI5D" ascii //weight: 1
        $x_1_2 = "9dXrelease.fromstheir7" ascii //weight: 1
        $x_1_3 = "thishavecommunicationDeveloperfamilyWqPOmnibox" ascii //weight: 1
        $x_1_4 = "BTheupafrom" ascii //weight: 1
        $x_1_5 = "Qdifferentf0Chrome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EM_2147793869_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EM!MTB"
        threat_id = "2147793869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LdrGetProcedureA" ascii //weight: 3
        $x_3_2 = "FFPGGLBM.pdb" ascii //weight: 3
        $x_3_3 = "IsBadHugeReadPtr" ascii //weight: 3
        $x_3_4 = "ScrollConsoleScreenBufferA" ascii //weight: 3
        $x_3_5 = "QueryUsersOnEncryptedFile" ascii //weight: 3
        $x_3_6 = "SHEnumerateUnreadMailAccountsW" ascii //weight: 3
        $x_3_7 = "YUMAfJBeta09:00installer." ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EM_2147793869_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EM!MTB"
        threat_id = "2147793869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "above.4Bour27nE" wide //weight: 1
        $x_1_2 = "UA9living" wide //weight: 1
        $x_1_3 = "abovePFemalexC0P0" wide //weight: 1
        $x_1_4 = "abundantly.uqyearscreepingmayYQTheir" wide //weight: 1
        $x_1_5 = "sElf.Exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EH_2147793909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EH!MTB"
        threat_id = "2147793909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "KF64-bitto4IncognitoIKinf" ascii //weight: 3
        $x_3_2 = "usageday,aCbacteriologyphoenixw" ascii //weight: 3
        $x_3_3 = "rrpiode.pdb" ascii //weight: 3
        $x_3_4 = "K5nlnot" ascii //weight: 3
        $x_3_5 = "MprAdminInterfaceTransportAdd" ascii //weight: 3
        $x_3_6 = "CopyEnhMetaFileW" ascii //weight: 3
        $x_3_7 = "SetupOpenLog" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EF_2147794075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EF!MTB"
        threat_id = "2147794075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "frponghrpOletnfercrr" ascii //weight: 3
        $x_3_2 = "kernel32.Sleep" ascii //weight: 3
        $x_3_3 = "rpidebbfll.pdb" ascii //weight: 3
        $x_3_4 = "llosewwq.ll" ascii //weight: 3
        $x_3_5 = "RpcMgmtIsServerListening" ascii //weight: 3
        $x_3_6 = "FtpFindFirstFileA" ascii //weight: 3
        $x_3_7 = "NotifyChangeEventLog" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GY_2147794132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GY!MTB"
        threat_id = "2147794132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 00 8a d8 2a da 80 eb ?? 88 1d ?? ?? ?? ?? 0f b7 da 83 c1 ?? 89 0d ?? ?? ?? ?? 39 1d ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 89 7d 00 89 3d ?? ?? ?? ?? 8d 3c 00 2b 3d ?? ?? ?? ?? 83 c5 04 2b fe 03 d7 83 6c 24 ?? 01 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EV_2147794224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EV!MTB"
        threat_id = "2147794224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 10 8a d1 83 c0 04 02 d2 03 c6 66 a3 ?? ?? ?? ?? b0 2d 2a c2 ba 30 0e 00 00 02 d8}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b7 c6 2b d0 83 c2 16 0f af d0 8b 07 69 d2 81 ea 00 00 89 15 ?? ?? ?? ?? 05 10 b3 07 01 89 07 83 c7 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EV_2147794224_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EV!MTB"
        threat_id = "2147794224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FPOLM.pdb" ascii //weight: 3
        $x_3_2 = "RpcStringBindingParseW" ascii //weight: 3
        $x_3_3 = "elf EX" ascii //weight: 3
        $x_3_4 = "ESTAPP E_" ascii //weight: 3
        $x_3_5 = "1ZModule,mechanisms1Sbc9W" ascii //weight: 3
        $x_3_6 = "RanaFcrintMAfhaveld" ascii //weight: 3
        $x_3_7 = "zijrecommendedwhichhistoryiCy" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GZ_2147794233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GZ!MTB"
        threat_id = "2147794233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 0e 81 c1 ?? ?? ?? ?? 89 0e 89 0d ?? ?? ?? ?? 8b ca 2b cf 69 c9 ?? ?? ?? ?? 02 db 2a 1d ?? ?? ?? ?? 66 03 c1 02 1d ?? ?? ?? ?? 83 c6 04 80 c3 ?? 83 ed 01 66 a3 ?? ?? ?? ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EC_2147794270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EC!MTB"
        threat_id = "2147794270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b0 e5 c6 44 24 33 74 8a 4c 24 33 8a 54 24 1f 88 54 24 51 38 c8 0f 84 17 ff ff ff eb 89 31 c0 c7 44 24 2c 1e 06}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EC_2147794270_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EC!MTB"
        threat_id = "2147794270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 74 21 65 21 21 7c 6a 74 85 6a 45 04 68 57 64 63 66 6a 74 40 75 cf 68 04 74 03 21 6a 78 64 64 8b 63 6a 74 68 05 78 85 6a 20 8b 66}  //weight: 1, accuracy: High
        $x_1_2 = "PEC2NO" ascii //weight: 1
        $x_1_3 = "golfinfo.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EC_2147794270_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EC!MTB"
        threat_id = "2147794270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6rule9abundantlyMademoveth,n" wide //weight: 1
        $x_1_2 = "2himgrass" wide //weight: 1
        $x_1_3 = "9kPDon.tbeastzsaidO" wide //weight: 1
        $x_1_4 = "xlet,rulet4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EC_2147794270_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EC!MTB"
        threat_id = "2147794270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Ge)Mod leH" ascii //weight: 3
        $x_3_2 = "LbraGyEx4" ascii //weight: 3
        $x_3_3 = "&Thus p>ggr=i c=jno@ belrun|mn" ascii //weight: 3
        $x_3_4 = "IObit" ascii //weight: 3
        $x_3_5 = "MailAsSmtpServer" ascii //weight: 3
        $x_3_6 = "UploadViaHttp" ascii //weight: 3
        $x_3_7 = "bugreport.txt" ascii //weight: 3
        $x_3_8 = "screenshot.png" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EG_2147794287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EG!MTB"
        threat_id = "2147794287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 7c 24 14 f7 d7 8b 5c 24 20 f7 d3 89 5c 24 3c 89 7c 24 38 88 14 08 eb 0b}  //weight: 10, accuracy: High
        $x_10_2 = {8a 44 24 0b 24 3b 8b 4d 10 8b 54 24 2c 88 44 24 37 39 ca}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EG_2147794287_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EG!MTB"
        threat_id = "2147794287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 57 fe 8b da 33 d2 2b d8 1b ea 0f b7 c6 99 2b d8 1b ea 03 cb 8b 5c 24 1c 13 dd 8b 6c 24 10}  //weight: 10, accuracy: High
        $x_10_2 = {0f b7 d6 be 0e 00 00 00 2b f2 2b f0 8b 45 00 05 0c 46 05 01 89 45 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EW_2147794288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EW!MTB"
        threat_id = "2147794288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 54 24 03 30 d2 8a 34 01 88 54 24 1b a1 ?? ?? ?? ?? 8b 4c 24 30 88 34 08 eb ac}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 44 24 30 83 c0 01 8b 4c 24 14 01 c9 89 4c 24 1c 89 44 24 30 eb c5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_QW_2147794340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.QW!MTB"
        threat_id = "2147794340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {03 c0 2b c7 83 ea 02 05 e1 95 ff ff 03 c3 83 fa 02 7f e7}  //weight: 10, accuracy: High
        $x_10_2 = {02 d1 8a c2 2c 2d 0f b6 c0 6a 0a 89 44 24 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_QW_2147794340_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.QW!MTB"
        threat_id = "2147794340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FGtkemvb" ascii //weight: 3
        $x_3_2 = "gopemiduyqwer" ascii //weight: 3
        $x_3_3 = "ByoldeerFoort" ascii //weight: 3
        $x_3_4 = "kernel32.Sleep" ascii //weight: 3
        $x_3_5 = "RTTYEBHUY.pdb" ascii //weight: 3
        $x_3_6 = "MprAdminTransportGetInfo" ascii //weight: 3
        $x_3_7 = "willOEfX" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_QW_2147794340_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.QW!MTB"
        threat_id = "2147794340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FGtkemvb" ascii //weight: 3
        $x_3_2 = "ddpeoirmkcvd.dll" ascii //weight: 3
        $x_3_3 = "VWelosdrmncdw" ascii //weight: 3
        $x_3_4 = "kernel32.Sleep" ascii //weight: 3
        $x_3_5 = "RTTYEBHUY.pdb" ascii //weight: 3
        $x_3_6 = "IsColorProfileValid" ascii //weight: 3
        $x_3_7 = "GetWindowPlacement" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_QW_2147794340_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.QW!MTB"
        threat_id = "2147794340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Ge)Mod leH" ascii //weight: 3
        $x_3_2 = "LbraGyEx4" ascii //weight: 3
        $x_3_3 = "&Thus p>ggr=i c=jno@ belrun|mn" ascii //weight: 3
        $x_3_4 = "KillTimer" ascii //weight: 3
        $x_3_5 = "SetProcessShutdownParameters" ascii //weight: 3
        $x_3_6 = "ShellExecuteExA" ascii //weight: 3
        $x_3_7 = "IsValidSid" ascii //weight: 3
        $x_3_8 = "GetSidIdentifierAuthority" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_QS_2147794354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.QS!MTB"
        threat_id = "2147794354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 84 0a 18 64 00 00 2b 45 e4 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 e9 18 64 00 00 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 e4 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 e4 8b 0d ?? ?? ?? ?? 2b c8 89 0d ?? ?? ?? ?? ba c5 01 00 00}  //weight: 10, accuracy: Low
        $x_3_2 = "Ge)Mod leH" ascii //weight: 3
        $x_3_3 = "LbraGyEx4" ascii //weight: 3
        $x_3_4 = "&Thus p>ggr=i c=jno@ belrun|mn" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_QM_2147794424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.QM!MTB"
        threat_id = "2147794424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c1 2b c6 83 c0 21 2b f1 8d 04 41}  //weight: 10, accuracy: High
        $x_10_2 = {8b ce 2b ca 8b d6 81 e9 35 f8 00 00}  //weight: 10, accuracy: High
        $x_3_3 = "mile\\Line.pdb" ascii //weight: 3
        $x_3_4 = "Bloodbroad" ascii //weight: 3
        $x_3_5 = "Rockline" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_QM_2147794424_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.QM!MTB"
        threat_id = "2147794424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FGtkemvb" ascii //weight: 3
        $x_3_2 = "mnuiehdbrwer" ascii //weight: 3
        $x_3_3 = "FporeoniYjdegtess" ascii //weight: 3
        $x_3_4 = "kernel32.Sleep" ascii //weight: 3
        $x_3_5 = "RTTYEBHUY.pdb" ascii //weight: 3
        $x_3_6 = "WinSCard" ascii //weight: 3
        $x_3_7 = "Jdidbrowser" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_QQ_2147794584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.QQ!MTB"
        threat_id = "2147794584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Th~s p5ggr6i c6jno; be" ascii //weight: 3
        $x_3_2 = "'bra,yEx?" ascii //weight: 3
        $x_3_3 = "MailAsSmtpServer" ascii //weight: 3
        $x_3_4 = "UploadViaHttp" ascii //weight: 3
        $x_3_5 = "screenshot.png" ascii //weight: 3
        $x_3_6 = "IObit" ascii //weight: 3
        $x_3_7 = "ScrShotZip" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_QD_2147794856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.QD!MTB"
        threat_id = "2147794856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "pull.pdb" ascii //weight: 3
        $x_3_2 = "slip\\wrong" ascii //weight: 3
        $x_3_3 = "pull.dll" ascii //weight: 3
        $x_3_4 = "Cloudstream" ascii //weight: 3
        $x_3_5 = "Humansurface" ascii //weight: 3
        $x_3_6 = "CryptUIWizImport" ascii //weight: 3
        $x_3_7 = "CryptUIDlgViewContext" ascii //weight: 3
        $x_3_8 = "CryptUIWizFreeDigitalSignContext" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BB_2147795410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BB!MTB"
        threat_id = "2147795410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BlinkbfixedwasFebruarythatdisplayedWebRTC.75JY" ascii //weight: 3
        $x_3_2 = "application.vNvstevereturn.theE" ascii //weight: 3
        $x_3_3 = "rpidebbfll.pdb" ascii //weight: 3
        $x_3_4 = "gpoiree" ascii //weight: 3
        $x_3_5 = "tokenythesPepper" ascii //weight: 3
        $x_3_6 = "Xaddtransferred2012,securityv" ascii //weight: 3
        $x_3_7 = "Alternatively,iJother,c" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BQ_2147795754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BQ!MTB"
        threat_id = "2147795754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/rnturtynurty.pdb" ascii //weight: 3
        $x_3_2 = "PostQuitMessage" ascii //weight: 3
        $x_3_3 = "RpcServerUseAllProtseqsIf" ascii //weight: 3
        $x_3_4 = "WerAddExcludedApplication" ascii //weight: 3
        $x_3_5 = "wer.dll" ascii //weight: 3
        $x_3_6 = "WerSysprepGeneralize" ascii //weight: 3
        $x_3_7 = "WerpAuxmdDumpRegisteredBlocks" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BR_2147795786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BR!MTB"
        threat_id = "2147795786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 54 24 4b 4c 8b 44 24 18 45 8a 0c 08 41 28 d1 4c 8b 54 24 08 45 88 0c 0a 8b 44 24 44 83 c0 20 89 44 24 34}  //weight: 10, accuracy: High
        $x_10_2 = {4c 8b 54 24 30 45 8a 1a 4c 89 4c 24 58 4c 8b 4c 24 10 45 88 1c 11}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AH_2147796003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AH!MTB"
        threat_id = "2147796003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 dd 00 00 00 00 2b c3 03 c0 03 c0 0f b7 c0 8a 0d ?? ?? ?? ?? 2a c8 80 e9 4c 02 d1 66 0f b6 c2 66 03 c3 66 83 c0 09 0f b7 c8 8b 06}  //weight: 10, accuracy: Low
        $x_10_2 = {02 c1 2c 61 02 d0 83 c6 04 83 ef 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AH_2147796003_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AH!MTB"
        threat_id = "2147796003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 14 01 8d 7c 17 17 8b d0 2b d1 03 d3 8d 0c 12 81 c6 94 3c 0a 01 8b d7 89 75 00 2b d1}  //weight: 10, accuracy: High
        $x_10_2 = {8b c1 6b c9 05 2b c6 83 c0 2c 03 ca 0f b7 15 ?? ?? ?? ?? 8b 75 00 2b d7 03 15 ?? ?? ?? ?? 8d 9c 01 d0 55 00 00 8b fa 8b d3 6b d2 05 03 d1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AH_2147796003_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AH!MTB"
        threat_id = "2147796003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "property_Still\\her.pdb" ascii //weight: 3
        $x_3_2 = "Modernmajor" ascii //weight: 3
        $x_3_3 = "MeRequire" ascii //weight: 3
        $x_3_4 = "INF_crcdisk" ascii //weight: 3
        $x_3_5 = "INF_wudfusbcciddriver" ascii //weight: 3
        $x_3_6 = "her.dll" ascii //weight: 3
        $x_3_7 = "re6wmislu" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AW_2147796014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AW!MTB"
        threat_id = "2147796014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b0 4a b1 24 8a 54 24 43 88 44 24 2b 88 d0 f6 e1 8a 4c 24 7f 88 84 24 98 00 00 00 8a 44 24 2b 38 c8}  //weight: 10, accuracy: High
        $x_10_2 = {31 d2 ba 14 35 09 00 39 d0 77 2d 83 c0 01 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AW_2147796014_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AW!MTB"
        threat_id = "2147796014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "moz2_slave" ascii //weight: 3
        $x_3_2 = "TestArray.pdb" ascii //weight: 3
        $x_3_3 = "Decimal@blink" ascii //weight: 3
        $x_3_4 = "IsProcessorFeaturePresent" ascii //weight: 3
        $x_3_5 = "IsDebuggerPresent" ascii //weight: 3
        $x_3_6 = "MOZ_ASSERT_UNREACHABLE" ascii //weight: 3
        $x_3_7 = "autoland-w32" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AW_2147796014_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AW!MTB"
        threat_id = "2147796014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LdrGetProcedureA" ascii //weight: 3
        $x_3_2 = "FFPGGLBM.pdb" ascii //weight: 3
        $x_3_3 = "ImmSetOpenStatus" ascii //weight: 3
        $x_3_4 = "SHEnumerateUnreadMailAccountsW" ascii //weight: 3
        $x_3_5 = "SHGetSpecialFolderPathA" ascii //weight: 3
        $x_3_6 = "PathRemoveBlanksW" ascii //weight: 3
        $x_3_7 = "CreateAsyncBindCtxEx" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AN_2147796267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AN!MTB"
        threat_id = "2147796267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 5c 24 18 4a 6b c7 2f 8b ca 2b c8 8a 04 1e 88 03 43 0f b7 c9 8b e9 89 5c 24 18}  //weight: 10, accuracy: High
        $x_10_2 = {66 2b c6 66 83 c0 41 0f b7 d0 8b 44 24 14 8d 5a 1a 05 50 b3 06 01 02 db a3 ?? ?? ?? ?? 89 84 2f 5a fa ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AD_2147796268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AD!MTB"
        threat_id = "2147796268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {29 3a 66 03 c9 66 03 ce b8 80 09 00 00 66 03 cf 8d 77 fe 66 2b c8 83 ea 08 0f b7 c1 03 f0}  //weight: 10, accuracy: High
        $x_10_2 = {66 83 c1 27 0f b7 d3 66 03 c2 66 03 c6 66 03 c1 8d 4b ff 0f b7 c0 03 c8 8a 44 24 10 04 27}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AD_2147796268_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AD!MTB"
        threat_id = "2147796268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 8a 42 07 00 00 57 8b f8 2b f9 8d 74 3e b6 0f af c6 03 c1 0f af c6 03 c1 8d b4 08 dd 19 ff ff 8a d8 0f af c6 03 c1}  //weight: 10, accuracy: High
        $x_3_2 = "Most.pdb" ascii //weight: 3
        $x_3_3 = "UnregisterHotKey" ascii //weight: 3
        $x_3_4 = "Growother" ascii //weight: 3
        $x_3_5 = "WordForce" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AD_2147796268_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AD!MTB"
        threat_id = "2147796268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rpidebbfll.pdb" ascii //weight: 3
        $x_3_2 = "SetupDiEnumDeviceInfo" ascii //weight: 3
        $x_3_3 = "DDplsoecrVwqase" ascii //weight: 3
        $x_3_4 = "gpoiree" ascii //weight: 3
        $x_3_5 = "GetIfTable" ascii //weight: 3
        $x_3_6 = "RegLoadAppKeyA" ascii //weight: 3
        $x_3_7 = "ldollirefgt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AQ_2147796697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AQ!MTB"
        threat_id = "2147796697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rrpiode.pdb" ascii //weight: 3
        $x_3_2 = "onupkreasoningChrome2RLZcInternet2008.28" ascii //weight: 3
        $x_3_3 = "modefromAbrowser.YG" ascii //weight: 3
        $x_3_4 = "usageday,aCbacteriologyphoenixw" ascii //weight: 3
        $x_3_5 = "FindFirstVolumeMountPointA" ascii //weight: 3
        $x_3_6 = "TG81-bitto4IncognitoIKinf" ascii //weight: 3
        $x_3_7 = "K5nlnot" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EJ_2147796855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EJ!MTB"
        threat_id = "2147796855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 c1 8d 44 10 f8 8b 54 24 10 8b 32 8a d3 2a d1 80 c2 7b}  //weight: 10, accuracy: High
        $x_10_2 = {8b 4c 24 10 8b d7 2b d3 81 ea 85 69 00 00 0f b7 da 81 c6 48 92 03 01 0f b7 d3 89 31 83 c1 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EN_2147797027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EN!MTB"
        threat_id = "2147797027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 0b 83 c3 04 0f b6 c8 66 83 c1 49 89 5c 24 14 66 03 4c 24 28 83 6c 24 20 01 66 8b f9 89 7c 24 10}  //weight: 10, accuracy: High
        $x_10_2 = {04 17 02 c0 02 c3 02 c1 02 c0 eb 07}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EN_2147797027_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EN!MTB"
        threat_id = "2147797027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e0 00 02 01 0b 01 00 00 00 40 03 00}  //weight: 2, accuracy: High
        $x_3_2 = {03 0c 60 2a 00 07 4a 10 01 03 01 00 04 00 10 00 01 00 0c 00 02 01 0a 8c 01 70 01 00 00 07 0b 27 0e 12}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EN_2147797027_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EN!MTB"
        threat_id = "2147797027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 8b 44 24 14 8b 3f 02 c7 89 7c 24 24 f6 d8 0f b6 fb 8a f8 89 4c 24 10}  //weight: 10, accuracy: High
        $x_10_2 = {89 07 b0 ce 2a 44 24 0f 83 c7 04 2a 05 ?? ?? ?? ?? 2a 44 24 10 02 d8 89 7c 24 1c 83 6c 24 20 01 8b 44 24 14}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ET_2147797089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ET!MTB"
        threat_id = "2147797089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 8b 4c 24 66 66 0b 4c 24 66 66 89 4c 24 66 66 8b 48 05 66 89 4c 24 5e 0f b7 44 24 5e 8b 54 24 28}  //weight: 10, accuracy: High
        $x_10_2 = {8a 08 0f b6 c1 83 f8 6a 88 4c 24 2f 89 44 24 28 0f 84 d3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ADQ_2147797593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ADQ!MTB"
        threat_id = "2147797593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FFRgpmdlwwWde" ascii //weight: 3
        $x_3_2 = "rpidebbfll.pdb" ascii //weight: 3
        $x_3_3 = "tocouldMozillascottP" ascii //weight: 3
        $x_3_4 = "multi-processusestAfterbymartin" ascii //weight: 3
        $x_3_5 = "RegOverridePredefKey" ascii //weight: 3
        $x_3_6 = "attackerininwhichgZa" ascii //weight: 3
        $x_3_7 = "chesterLinux.43Mmain9S" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ADM_2147797594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ADM!MTB"
        threat_id = "2147797594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FFRgpmdlwwWde" ascii //weight: 3
        $x_3_2 = "rpidebbfll.pdb" ascii //weight: 3
        $x_3_3 = "kernel32.Sleep" ascii //weight: 3
        $x_3_4 = "SHGetDesktopFolder" ascii //weight: 3
        $x_3_5 = "RegOverridePredefKey" ascii //weight: 3
        $x_3_6 = "SetupDiEnumDeviceInfo" ascii //weight: 3
        $x_3_7 = "hhooewdaqsx" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ADM_2147797594_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ADM!MTB"
        threat_id = "2147797594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "EnumSystemLocalesA" ascii //weight: 3
        $x_3_2 = "Magnetquotient" ascii //weight: 3
        $x_3_3 = "no.pdb" ascii //weight: 3
        $x_3_4 = "GetWindowsDirectoryA" ascii //weight: 3
        $x_3_5 = "FlushFileBuffers" ascii //weight: 3
        $x_3_6 = "SetConsoleCtrlHandler" ascii //weight: 3
        $x_3_7 = "OutputDebugStringA" ascii //weight: 3
        $x_3_8 = "GetStartupInfoA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ADJ_2147797596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ADJ!MTB"
        threat_id = "2147797596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 11 88 10 8b 45 f4 83 c0 01 89 45 f4 8b 4d f0 83 c1 01 89 4d f0 8b 55 dc 83 ea 31 8b 45 e0 83 d8 00 33 c9 03 55 fc 13 c1}  //weight: 10, accuracy: High
        $x_10_2 = {83 ea 09 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 09 2b 05 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? 8b 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AB_2147797680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AB!MTB"
        threat_id = "2147797680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 04 4a 89 7d c4 8d 56 f9 03 55 d0 81 c7 ed 1e 00 00 03 c7 8d be 8b 1e ff ff 0f b7 c8 8b c6 83 c0 f3 03 45 d0 03 c1 2b c8 8b c6 03 45 d0 03 ce 69 c0 38 f9 00 00 8d 0c c9 c1 e1 02 2b c8 8d 86 29 d0 06 00 2b ca 8b 55 d0 03 4d c4 03 c1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AB_2147797680_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AB!MTB"
        threat_id = "2147797680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 8d b4 e6 ff ff 8b 45 0c 0f b6 00 83 f8 31 ?? ?? 83 f8 35 ?? ?? 33 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ADS_2147797953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ADS!MTB"
        threat_id = "2147797953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "pair.pdb" ascii //weight: 3
        $x_3_2 = "decide_page\\Favor-chick" ascii //weight: 3
        $x_3_3 = "Little So" ascii //weight: 3
        $x_3_4 = "GetProcessWindowStation" ascii //weight: 3
        $x_3_5 = "GetUserObjectInformationA" ascii //weight: 3
        $x_3_6 = "SystemFunction036" ascii //weight: 3
        $x_3_7 = "IsDebuggerPresent" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DW_2147798404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DW!MTB"
        threat_id = "2147798404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "hReachappear.1529ChromiumFacebook" ascii //weight: 3
        $x_3_2 = "p25menu,quicker,Gwilliesitesdexterand" ascii //weight: 3
        $x_3_3 = "canadaHywinstonbefore" ascii //weight: 3
        $x_3_4 = "Betatreeking3seecesesoeving.123forXemetif" ascii //weight: 3
        $x_3_5 = "Cheemeeherinitiatedy777777byE" ascii //weight: 3
        $x_3_6 = "SHEnumerateUnreadMailAccountsW" ascii //weight: 3
        $x_3_7 = "FFPGGLBM.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DW_2147798404_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DW!MTB"
        threat_id = "2147798404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "InternetOpen" ascii //weight: 2
        $x_2_2 = "VirtualProtect" ascii //weight: 2
        $x_2_3 = "VirtualAlloc" ascii //weight: 2
        $x_2_4 = "http://" ascii //weight: 2
        $x_2_5 = "test.bhBl360.co" ascii //weight: 2
        $x_2_6 = "m/001/puppe" ascii //weight: 2
        $x_2_7 = ".exeY" ascii //weight: 2
        $x_2_8 = "HTTP/1.1" ascii //weight: 2
        $x_2_9 = "ShxJwpLShxJwpLShxJwpL" ascii //weight: 2
        $x_2_10 = "ua3lwcy1Wua3lwcy1Wua3lwcy1" ascii //weight: 2
        $x_2_11 = "gdq6QSqbV7mVpRgdq6QSqbV7mVpRgdq6QSqbV7mVpR" ascii //weight: 2
        $x_2_12 = "ggo971ggo97187KAyRpGUrAwNq" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DF_2147798406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DF!MTB"
        threat_id = "2147798406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ba 03 00 00 00 0f c2 c8 02 83 c2 04 83 c2 04}  //weight: 10, accuracy: High
        $x_10_2 = {29 d7 19 c6 89 74 24 14 89 7c 24 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DF_2147798406_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DF!MTB"
        threat_id = "2147798406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "F3dYPine" ascii //weight: 3
        $x_3_2 = "ewvtw34" ascii //weight: 3
        $x_3_3 = "FindFirstUrlCacheEntryExA" ascii //weight: 3
        $x_3_4 = "DeletePrinterDriverExW" ascii //weight: 3
        $x_3_5 = "InitiateSystemShutdownExW" ascii //weight: 3
        $x_3_6 = "GetNumberOfEventLogRecords" ascii //weight: 3
        $x_3_7 = "GetClipboardFormatNameW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DG_2147798407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DG!MTB"
        threat_id = "2147798407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b c0 62 2b c1 8b 3d ?? ?? ?? ?? 8b d7 6b d2 4d 8d 54 10 62 a1 ?? ?? ?? ?? 03 c1 3d 65 03}  //weight: 10, accuracy: Low
        $x_10_2 = {2b c1 05 59 a0 00 00 a3 ?? ?? ?? ?? 81 c2 00 cf 7e 01 89 15 ?? ?? ?? ?? 89 94 37 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 8b c8 6b c9 1b 03 cb 83 c6 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_R_2147799379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.R!MTB"
        threat_id = "2147799379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 d1 89 c8 99 f7 fe 8b 4d e0 8a 3c 11 8b 75 cc 88 3c 31 88 1c 11 0f b6 0c 31 01 f9 81 e1 ff 00 00 00 8b 7d e8 8b 75 d0 8a 1c 37 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d0 88 1c 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_CW_2147799492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.CW!MTB"
        threat_id = "2147799492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {81 f6 4b 9a f7 94 2b 75 20 83 c6 2b 81 ee 2c 37 7c a4}  //weight: 10, accuracy: High
        $x_10_2 = {03 4d 20 83 e9 13 81 f1 fa 2b 8d e2 03 c8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SIB_2147799607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SIB!MTB"
        threat_id = "2147799607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 [0-74] 8a 04 0a [0-5] 8a 64 24 27 28 e0 [0-10] 89 4c 24 10 [0-5] 89 74 24 08 88 44 24 07 [0-26] 8b 44 24 08 8b 54 24 10 8a 5c 24 07 88 1c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RPM_2147805659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RPM!MTB"
        threat_id = "2147805659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 cf 4a 89 4c 24 34 89 54 24 2c 8a 00 88 85 ?? ?? ?? ?? 45 8b 44 24 24 8b 3d ?? ?? ?? ?? 03 c0 89 6c 24 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_QE_2147806018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.QE!MTB"
        threat_id = "2147806018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 44 24 4f f9 8a 5c 24 7f 80 c3 e3 88 5c 24 7f 8a 18 89 4c 24 78 0f b6 c3 66 8b 74 24 74 83 f8 6a 89 4c 24 34 66 89 74 24 32}  //weight: 10, accuracy: High
        $x_3_2 = "FFPGGLBM.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_QV_2147806068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.QV!MTB"
        threat_id = "2147806068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "RTTYEBHUY.pdb" ascii //weight: 3
        $x_3_2 = "willOEfX" ascii //weight: 3
        $x_3_3 = "WinSCard.dll" ascii //weight: 3
        $x_3_4 = "InternetSetStatusCallback" ascii //weight: 3
        $x_3_5 = "kernel32.Sleep" ascii //weight: 3
        $x_3_6 = "Jdidbrowser" ascii //weight: 3
        $x_3_7 = "WINSPOOL.DRV" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_WE_2147807324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.WE!MTB"
        threat_id = "2147807324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LdrGetProcedureA" ascii //weight: 3
        $x_3_2 = "testsvictoria4benchmarks,submissions" ascii //weight: 3
        $x_3_3 = "CreateHatchBrush" ascii //weight: 3
        $x_3_4 = "GetRandomRgn" ascii //weight: 3
        $x_3_5 = "FlashLstandardsuch5Stable" ascii //weight: 3
        $x_3_6 = "DefDlgProcW" ascii //weight: 3
        $x_3_7 = "LockWindowUpdate" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_2147807387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.dwuq!MTB"
        threat_id = "2147807387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "dwuq: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://www.besthotel360.com:1219/001/puppet.Txt" ascii //weight: 2
        $x_2_2 = "http/1.1" ascii //weight: 2
        $x_2_3 = "http/1.0" ascii //weight: 2
        $x_2_4 = "eLgmpHxuN1j4oEceLgmpHxuN1j4oEceLgmpHxuN1j4oEc" ascii //weight: 2
        $x_2_5 = "YcRtuNjmT0b1YcRtuNjmT0b1YcRtuNjmT0b1" ascii //weight: 2
        $x_2_6 = "OGb2GKZsOGb2GKZsOGb2GKZs" ascii //weight: 2
        $x_2_7 = "HoUSgM3CZHoUSgM3CZHoUSgM3CZ" ascii //weight: 2
        $x_2_8 = "6TTHr6TTHr6TTHr" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_CE_2147807412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.CE!MTB"
        threat_id = "2147807412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 c0 01 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc 83 c0 02 83 c0 02 83 e8 02 83 e8 02 cc 83 c0 02 83 e8 02}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_CE_2147807412_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.CE!MTB"
        threat_id = "2147807412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "1Chrome,aXMsuchmQ" ascii //weight: 3
        $x_3_2 = "Googleand3m" ascii //weight: 3
        $x_3_3 = "athekTZX" ascii //weight: 3
        $x_3_4 = "qoenwoiderd.dll" ascii //weight: 3
        $x_3_5 = "DfoerFopqwdfrs" ascii //weight: 3
        $x_3_6 = "kernel32.Sleep" ascii //weight: 3
        $x_3_7 = "RFFGTEQ.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_2147807555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.lmnq!MTB"
        threat_id = "2147807555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "lmnq: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 44 24 48 24 01 0f b6 c8 89 4c 24 40 66 8b 54 24 5e 66 33 54 24 5e 66 89 54 24 5e e9 ?? ?? ?? ?? 8b 44 24 44 0f b6 40 04 3d cd 00 00 00 0f 94 c1 80 e1 01 88 4c 24 48 eb c6 0f b6 44 24 1f 8a 4c 24 4a 80 e1 01 88 4c 24 48 83 f8 50 74 d2 eb af}  //weight: 10, accuracy: Low
        $x_10_2 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 31 c0 31 d2 42 ba ?? ?? ?? ?? 39 d0 77 2d 83 c0 01 83 c0 02 83 e8 02 cc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ED_2147807872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ED!MTB"
        threat_id = "2147807872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 f4 8b 45 08 8a 08 8a 55 f3 80 e2 18 0f be c1 88 55 f3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_FA_2147808368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.FA!MTB"
        threat_id = "2147808368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 94 08 f8 00 00 00 89 54 24 38 8b 84 08 94 00 00 00 89 84 24 80 00 00 00 8b 44 24 38 8b 8c 24 80 00 00 00 31 c8 89 44 24 38 8b 44 24 38 03 44 24 44 89 44 24 44}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GN_2147808635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GN!MTB"
        threat_id = "2147808635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 cf 36 ea 2e 5d [0-6] 0f b6 fc 29 f9 88 cc 88 65 ?? 8b 4d ?? 8b 7d ?? 8a 65 ?? 88 24 0f 88 45 ?? 89 75 ?? 89 55 ?? 83 c4 18}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GO_2147808663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GO!MTB"
        threat_id = "2147808663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RFFGTEQ.pdb" ascii //weight: 1
        $x_1_2 = "qoenwoiderd.dll" ascii //weight: 1
        $x_1_3 = "LdrGetProcedureA" ascii //weight: 1
        $x_1_4 = "OutputDebugStringA" ascii //weight: 1
        $x_1_5 = "DfoerFopqwdfrs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RST_2147808753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RST!MTB"
        threat_id = "2147808753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ioinloie8RRieTdTieTrevTmTnes" ascii //weight: 1
        $x_1_2 = "7inrnPaedoraasMaelowse" ascii //weight: 1
        $x_1_3 = "reeKir74rZDvrrrirn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_FC_2147808832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.FC!MTB"
        threat_id = "2147808832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 08 0f b6 c1 83 f8 6a 88 4c 24 29 89 44 24 24}  //weight: 10, accuracy: High
        $x_10_2 = {8a 08 8a 54 24 29 80 e2 d8 88 54 24 5d 0f b6 c1 3d b8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_FD_2147808833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.FD!MTB"
        threat_id = "2147808833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FFPGGLBM.pdb" ascii //weight: 3
        $x_3_2 = "WTHelperGetProvSignerFromChain" ascii //weight: 3
        $x_3_3 = "MprInfoRemoveAll" ascii //weight: 3
        $x_3_4 = "SetupSetFileQueueAlternatePlatformW" ascii //weight: 3
        $x_3_5 = "download" ascii //weight: 3
        $x_3_6 = "TheTaf" ascii //weight: 3
        $x_3_7 = "Hinto45i" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_HMP_2147809086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.HMP!MTB"
        threat_id = "2147809086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://FileAp" ascii //weight: 1
        $x_1_2 = "WinHttpOpen" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "i.gyao.top/001/puppe" ascii //weight: 1
        $x_1_5 = "809.1gSafari6k" ascii //weight: 1
        $x_1_6 = "fGg67Hhli89JjKkLlMmNnOoPpQq" ascii //weight: 1
        $x_1_7 = "/ekernel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DE_2147809090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DE!MTB"
        threat_id = "2147809090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 4c 24 50 83 f8 6a 89 44 24 24 0f 84 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 44 24 30 8d 65 fc 5e 5d c3 a1 ?? ?? ?? ?? 0f b6 00 3d b8 00 00 00 0f 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_DE_2147809090_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.DE!MTB"
        threat_id = "2147809090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 16 01 d1 35 ?? ?? ?? ?? 89 45 ?? 89 c8 99 8b 4d ?? f7 f9 8b 75 ?? 89 16 8b 55 ?? 8b 0a 8b 55 ?? 8b 12 0f b6 0c 0a 8b 16 8b 75 ?? 8b 36 0f b6 14 16 31 d1 88 cb 8b 4d ?? 8b 11 8b 75 ?? 8b 0e 88 1c 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ER_2147809476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ER!MTB"
        threat_id = "2147809476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 c0 01 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RQIJ_2147809628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RQIJ!MTB"
        threat_id = "2147809628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bbmeeomnvpop.dll" ascii //weight: 1
        $x_1_2 = "RFFGTEQ.pdb" ascii //weight: 1
        $x_1_3 = "BlockInput" ascii //weight: 1
        $x_1_4 = "tobitegate.205andtaulsomewhatL" ascii //weight: 1
        $x_1_5 = "bz1851monbcabcorespubsyepChbobium6" ascii //weight: 1
        $x_1_6 = "thatmodenser1areB" ascii //weight: 1
        $x_1_7 = "prevbousMnupportauto-upbbting" ascii //weight: 1
        $x_1_8 = "Rbrebeabedtbeypoints.6bIn15345678Kl" ascii //weight: 1
        $x_1_9 = "BpodmsseliocDfrtoo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GBC_2147811345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GBC!MTB"
        threat_id = "2147811345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {64 89 25 00 00 00 00 33 c0 3d 12 35 01 00 73 07 cc cc 40 cc cc eb f2 58 64 a3 00 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_M_2147812419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.M!MTB"
        threat_id = "2147812419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Orderdictionary\\Silent.pdb" ascii //weight: 3
        $x_3_2 = "PSCredential" ascii //weight: 3
        $x_3_3 = "GetProcessWindowStation" ascii //weight: 3
        $x_3_4 = "GetSystemTimePreciseAsFileTime" ascii //weight: 3
        $x_3_5 = "IsDebuggerPresent" ascii //weight: 3
        $x_3_6 = "GetStartupInfoW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_ABA_2147812777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.ABA!MTB"
        threat_id = "2147812777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "besthotel360.com:1219/001/puppet.Txt" ascii //weight: 1
        $x_1_2 = "InternetConnect" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "HTTP/1.1" ascii //weight: 1
        $x_1_6 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_7 = "qYM8CTbqYM8CTbqYM8CTb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_E_2147813753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.E!MTB"
        threat_id = "2147813753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "@echo off" ascii //weight: 3
        $x_3_2 = "del /F /Q /A" ascii //weight: 3
        $x_3_3 = "HTTP/1.0" ascii //weight: 3
        $x_3_4 = "AM6ziObAkkVHtrvZFziejahX" ascii //weight: 3
        $x_3_5 = "vClz4nZubNU8dZlK" ascii //weight: 3
        $x_3_6 = "V6bdlMGyN35YV" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_GI_2147815240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.GI!MTB"
        threat_id = "2147815240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cfileapi.gyx" ascii //weight: 1
        $x_1_2 = "WinHttpOpen" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "VMProtect begin" ascii //weight: 1
        $x_1_5 = "ao.top/001/puppe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BX_2147816723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BX!MTB"
        threat_id = "2147816723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 0c 35 ?? ?? ?? ?? 89 45 f0 eb 03 8d 49 00 8b 07 8a 0c 30 03 c6 33 d2 88 8d ?? ?? ?? ?? 84 c9 74 23}  //weight: 5, accuracy: Low
        $x_5_2 = {64 a1 18 00 00 00 8b 40 30 81 fb ?? ?? ?? ?? 75 17 8b 40 08 5b 8b e5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BXF_2147817817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BXF!MTB"
        threat_id = "2147817817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 75 c0 89 16 8b 55 c8 8b 0a 8b 55 b8 8b 12 0f b6 0c 0a 8b 16 8b 75 c4 8b 36 0f b6 14 16 31 d1 88 cb 8b 4d c8 8b 11 8b 75 b4 8b 0e 88 1c 11 e9 e4 fe ff ff}  //weight: 10, accuracy: High
        $x_1_2 = "\\town\\where\\ahung.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_FT_2147818395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.FT!MTB"
        threat_id = "2147818395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 0c 66 8b 18 8b 44 24 2c 89 74 24 30 be ?? ?? ?? ?? 29 c6 89 74 24 28 8b 44 24 1c 35 b5 d4 2b 6e 8b 74 24 18 89 74 24 3c 89 44 24 38 66 39 fb}  //weight: 10, accuracy: Low
        $x_1_2 = "1theidentifier1182016password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_BN_2147823117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.BN!MTB"
        threat_id = "2147823117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b f0 2b f3 83 ee 07 8b d6 0f af d0 2b d3 0f af d1 2b d3 8d 42 1c 02 c3 00 44 24 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EK_2147832383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EK!MTB"
        threat_id = "2147832383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "riginal-shine\\bat\\Cat\\page" ascii //weight: 1
        $x_1_2 = "Design.dll" ascii //weight: 1
        $x_1_3 = "Forcearea" ascii //weight: 1
        $x_1_4 = "Stationmeat" ascii //weight: 1
        $x_1_5 = "lOwWTOw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_EB_2147832942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.EB!MTB"
        threat_id = "2147832942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ba 03 00 00 00 0f c2 c8 02 83 c2 04 83 c2 04 83 c2 04 83 c2 04 83 c2 04 83 c2 04}  //weight: 5, accuracy: High
        $x_1_2 = "RFFGTEQ.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RPG_2147833681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RPG!MTB"
        threat_id = "2147833681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 37 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d0 88 1c 31 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_CB_2147838540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.CB!MTB"
        threat_id = "2147838540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 0c 37 88 0e 0f b6 1d ?? ?? ?? ?? 83 e8 01 8a ca 2a c8 80 c1 2d 0f b6 c9 83 c6 01 3b 1d ?? ?? ?? ?? 8d 4c 11}  //weight: 10, accuracy: Low
        $x_5_2 = "own\\Store\\Once\\Boat\\agree\\Men\\Mile\\Willmagnet.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_CB_2147838540_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.CB!MTB"
        threat_id = "2147838540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HaveHgrassdeepNHis" ascii //weight: 1
        $x_1_2 = "5KAsignssgodvoidamorning." ascii //weight: 1
        $x_1_3 = "were,wplacetreemovethHRcan.t" ascii //weight: 1
        $x_1_4 = "fgreater.Qdivided.m6U2" ascii //weight: 1
        $x_1_5 = "ef6jdaycreepethmakeVHsubdue" ascii //weight: 1
        $x_1_6 = "K79The0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_CV_2147840574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.CV!MTB"
        threat_id = "2147840574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NArthereR7everyh" ascii //weight: 1
        $x_1_2 = "isn.t,fill,set,Alivingtree" ascii //weight: 1
        $x_1_3 = "isn.t.air,whoseH4Cc" ascii //weight: 1
        $x_1_4 = "eUnderdarknessbemeatto.give" ascii //weight: 1
        $x_1_5 = "Cfish.the.mAP" ascii //weight: 1
        $x_1_6 = "SETUPAPI.dll" ascii //weight: 1
        $x_1_7 = "CoDosDateTimeToFileTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_CAI_2147843451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.CAI!MTB"
        threat_id = "2147843451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "creepingChath7rulesayingwhosetree" ascii //weight: 2
        $x_2_2 = "seedmZyouDreplenishdayn" ascii //weight: 2
        $x_2_3 = "Itselfunderdividedhmovethlikenessfruitfula" ascii //weight: 2
        $x_2_4 = "GseasonswhichtheiragrassoUonefly" ascii //weight: 2
        $x_2_5 = "CreateTimerQueue" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RPX_2147888901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RPX!MTB"
        threat_id = "2147888901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 e0 89 45 b0 8d 45 d8 89 45 ac 8b 45 b0 89 4d a8 8b 4d ac 89 48 0c 89 58 04 8b 4d a8 89 08 c7 40 08 04 00 00 00 89 7d a4 89 55 a0 89 75 9c ff d2}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d ec 8b 55 e0 8a 3c 11 28 df 8b 75 e8 88 3c 16 81 c2 01 00 00 00 8b 7d f0 39 fa 89 55 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dridex_RR_2147895851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RR!MTB"
        threat_id = "2147895851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 3c 2d 65 73 2d c7 44 24 40 2d 70 70 2d c7 44 24 44 2d 2d 2d 00 88 c2 80 c2 5b 34 7c 88 4c 24 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_KS_2147896072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KS!MTB"
        threat_id = "2147896072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 9d ad ba 1e dc 49 4a ce 23 6b 29 c3 1b b9 fd 9b 1e 23 3e 80 f8 cd 98 c9 07 35 f4 78 d4 d2 cf 89 d1 c1 06 ff 7c 49 7d cd 0f 6a 3d 0f e7 99 fd 1b 1e 23 3e 4d 17 9a 18 69 bb 81 d4 58 88 1e 6f}  //weight: 10, accuracy: High
        $x_3_2 = "ESTAPPPexe" ascii //weight: 3
        $x_3_3 = "tttt32" ascii //weight: 3
        $x_3_4 = "Rpkder336" ascii //weight: 3
        $x_3_5 = "fpmvppp.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_KA_2147896073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.KA!MTB"
        threat_id = "2147896073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b b3 37 92 66 db 02 5e aa 37 1e 47 e4 5f 3b d9 61 38 fc 2d 9b 64 55 fd 1e 8b 22 cd e0 e4 8d f4 eb 7f 37 12 9a bc 16 7d 2b 37 ff 33 44 7f 08 8d 15 38 9c f9 67 e3 09 b1 fe 8b 41 ae 60 84}  //weight: 10, accuracy: High
        $x_3_2 = "EFRE65.pdb" ascii //weight: 3
        $x_3_3 = "tttt32" ascii //weight: 3
        $x_3_4 = "estapp" ascii //weight: 3
        $x_3_5 = "Wallowingt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_RE_2147899272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.RE!MTB"
        threat_id = "2147899272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 1c 38 8b 2b 89 ce 31 ee 89 33 8d 5f 04 89 df 8b 5a 08 39 fb 77 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AMMC_2147904785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AMMC!MTB"
        threat_id = "2147904785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BoenzieelioarhhhI" ascii //weight: 2
        $x_2_2 = "indsqdrq50.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_Z_2147912175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.Z!MTB"
        threat_id = "2147912175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b cb 33 d6 4a 02 c4 2b da 8b d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AZA_2147913346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AZA!MTB"
        threat_id = "2147913346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 40 32 16 8b 74 24 18 88 14 0e 03 44 24 3c 8b 4c 24 38 89 4c 24 64 89 44 24 ?? 8b 4c 24 34 89 4c 24 44 8b 4c 24 30 39 c8 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SOZC_2147920101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SOZC!MTB"
        threat_id = "2147920101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 88 45 ff 8a 45 ff a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 83 c4 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_AMAJ_2147920204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.AMAJ!MTB"
        threat_id = "2147920204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c ?? 4d 08 8a 15 ?? ?? ?? ?? 88 c4 30 cc 00 c2 88 15 ?? ?? ?? ?? 88 0d 01 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ff ff 0f b6 c4 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_SZUK_2147920644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.SZUK!MTB"
        threat_id = "2147920644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 4d 08 8b 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 30 c8 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_MWV_2147932055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.MWV!MTB"
        threat_id = "2147932055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 d7 8b 54 24 34 8b 74 24 10 29 f2 89 54 24 58 89 7c 24 38 35 3a ce 26 18 09 c8 c7 44 24 ?? ad 85 92 7a 89 44 24 04 74 b0 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_UYZ_2147933326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.UYZ!MTB"
        threat_id = "2147933326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 f9 8b 7c 24 20 8b 74 24 08 8a 1c 37 81 e1 ff 00 00 00 8b 74 24 18 32 1c 0e 8b 4c 24 1c 8b 74 24 08 88 1c 31 83 c6 01 8b 4c 24 ?? 39 ce 8b 4c 24 04 89 4c 24 0c 89 74 24 10 89 54 24 14 0f 84}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dridex_UHD_2147934520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dridex.UHD!MTB"
        threat_id = "2147934520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 f8 88 c2 0f b6 c2 8b 7c 24 10 8a 14 07 8b 44 24 18 8a 34 08 30 f2 8b 44 24 ?? 88 14 08 41 c7 44 24 ?? 00 00 00 00 c7 44 24 20 84 46 b0 4d 8b 44 24 1c 39 c1 89 4c 24 08 89 74 24 04 89 5c 24 0c 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


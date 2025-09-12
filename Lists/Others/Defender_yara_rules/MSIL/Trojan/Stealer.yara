rule Trojan_MSIL_Stealer_ML_2147744918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ML!MTB"
        threat_id = "2147744918"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 08 09 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 04 11 04 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 13 05 11 05 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 13 06 73 ?? ?? ?? ?? 13 07 11 06 6f ?? ?? ?? ?? 14 17 8d ?? ?? ?? ?? 25 16 11 07 6f ?? ?? ?? ?? a2 6f ?? ?? ?? ?? 26 20 ?? ?? ?? ?? 13 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_2147753940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer!MTB"
        threat_id = "2147753940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WebResponse" ascii //weight: 1
        $x_1_2 = "GetResponse" ascii //weight: 1
        $x_1_3 = "GetResourceString" ascii //weight: 1
        $x_1_4 = "AppDomain" ascii //weight: 1
        $x_1_5 = "WebServices" ascii //weight: 1
        $x_1_6 = "GetExportedTypes" ascii //weight: 1
        $x_1_7 = "WebRequest" ascii //weight: 1
        $x_1_8 = "XO-JAM." ascii //weight: 1
        $x_1_9 = "_TPassword" ascii //weight: 1
        $x_1_10 = "CO-JAM." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_MSIL_Stealer_RS_2147764475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.RS!MTB"
        threat_id = "2147764475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4950378E151B59040AC94666E4F0AF32484E4D13C4CE37A7A1A91ED7CBD94EB7" ascii //weight: 1
        $x_1_2 = "62qbqbc38oosb]1Fqe]db1Ccc_f" ascii //weight: 1
        $x_1_3 = "08cpdp_85a_po_8Asfpo]8Es_]dd0Aqqo_-F8edbe" ascii //weight: 1
        $x_1_4 = "5Ecedc" ascii //weight: 1
        $x_1_5 = "D0srq" ascii //weight: 1
        $x_1_6 = "c60eq" ascii //weight: 1
        $x_1_7 = "pb9BnecsbF8]aq" ascii //weight: 1
        $x_1_8 = "9Bbano]FEapaceD6sbnfr8" ascii //weight: 1
        $x_1_9 = {52 65 73 6f 75 72 63 65 44 69 63 74 69 6f 6e 61 72 79 4c 6f 63 61 74 69 6f 6e 00 53 79 73 74 65 6d 2e 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 00 53 79 73 74 65 6d 2e 47 6c 6f 62 61 6c 69 7a 61 74 69 6f 6e 00 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 53 65 72 69 61 6c 69 7a 61 74 69 6f 6e 00 53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 00 53 71 6c 50 61 72 61 6d 65 74 65 72 43 6f 6c 6c 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_MSIL_Stealer_SM_2147764523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SM!MTB"
        threat_id = "2147764523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$2dfb5bea-c5b3-4639-8d37-b6149d665eca" ascii //weight: 2
        $x_2_2 = "Pillager\\obj\\Release\\Pillager.pdb" ascii //weight: 2
        $x_2_3 = "Pillager.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ZA_2147765244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ZA!MTB"
        threat_id = "2147765244"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MjA5LjEyNi44MS40Mg==" wide //weight: 1
        $x_1_2 = "QzpcVXNlcnM=" wide //weight: 1
        $x_1_3 = "cm9vdFxTZWN1cml0eUNlbnRlcjI=" wide //weight: 1
        $x_1_4 = "UFJPQ0VTU09SX0FSQ0hJVEVDVFVSRQ==" wide //weight: 1
        $x_1_5 = "U0VMRUNUICogRlJPTSBBbnRpVmlydXNQcm9kdWN0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SF_2147765656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SF!MTB"
        threat_id = "2147765656"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tram pn{not or-run v{-DOS z|qe" ascii //weight: 1
        $x_1_2 = "shryy32.dyy" ascii //weight: 1
        $x_1_3 = "kernry@2" ascii //weight: 1
        $x_1_4 = "Iva{-Zedveqr" ascii //weight: 1
        $x_1_5 = "A4FE45FD46AA63601CFDA4BB5B7E279A21E1D6E263AC3F78F27BEF4269DC2011" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SX_2147772864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SX!MTB"
        threat_id = "2147772864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 2d 00 00 0a 06 28 ?? ?? ?? 0a 0c 08 73 2e 00 00 0a 02 28 2f 00 00 0a 28 ?? ?? ?? 0a 73 1b 00 00 0a 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_MZ_2147773187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.MZ!MTB"
        threat_id = "2147773187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 17 9c 25 0c 28 ?? ?? 00 0a 0d 08 16 91 2d 02 2b 1e 07 16 9a 28 ?? ?? 00 0a d0 01 00 00 1b 28 ?? ?? 00 0a 28 ?? ?? 00 0a 74 01 00 00 1b 10 00 09 74 ?? ?? 00 01 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_A_2147793858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.A!MSR"
        threat_id = "2147793858"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BlockCopy" ascii //weight: 1
        $x_1_2 = {50 00 75 00 72 00 65 00 4d 00 69 00 6e 00 65 00 72 00 5f 00 53 00 68 00 61 00 72 00 65 00 64 00 5c 00 6f 00 62 00 6a 00 5c 00 44 00 65 00 62 00 75 00 67 00 5c 00 43 00 6c 00 61 00 73 00 73 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 ?? 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_3 = {50 75 72 65 4d 69 6e 65 72 5f 53 68 61 72 65 64 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 6c 61 73 73 4c 69 62 72 61 72 79 ?? 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_4 = "IPackBotKiller" ascii //weight: 1
        $x_1_5 = "IPackMining" ascii //weight: 1
        $x_1_6 = "IPackLogger" ascii //weight: 1
        $x_1_7 = "AesCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_MSIL_Stealer_A_2147798773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.A!MTB"
        threat_id = "2147798773"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$7BE8A262-AA9F-46F4-BDDD-16C4394503C2" ascii //weight: 1
        $x_1_2 = "andre\\RiderProjects\\mApp\\mApp\\obj" ascii //weight: 1
        $x_1_3 = "mApp.pdb" ascii //weight: 1
        $x_1_4 = "https://andruxa.pp.ua/dsfg/dll.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_USV_2147799520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.USV!MTB"
        threat_id = "2147799520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\USER\\AppData\\Roaming\\System\\jobs" ascii //weight: 1
        $x_1_2 = "HideModuleNameAttribute" ascii //weight: 1
        $x_1_3 = "AssemblyTrademarkAttribute" ascii //weight: 1
        $x_1_4 = "NewLateBinding" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_KA_2147805770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.KA!MTB"
        threat_id = "2147805770"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\myfile.txt" ascii //weight: 1
        $x_1_2 = "c:\\file\\re.bat" ascii //weight: 1
        $x_1_3 = "H:\\reader.exe" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\reader.exe" ascii //weight: 1
        $x_1_5 = "$951006a7-b02f-43b0-9313-f948f28ab5fa" ascii //weight: 1
        $x_1_6 = "C:\\file\\sam.zip" ascii //weight: 1
        $x_1_7 = "DiposeHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_CB_2147815646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.CB!MTB"
        threat_id = "2147815646"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 ff 03 3e 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 38 01 00 00 32 01 00 00 bb 04 00 00 49 0f 00 00 6f 09 00 00 3c 00 00 00 a7 03}  //weight: 3, accuracy: High
        $x_3_2 = "System.Security.Cryptography.AesCryptoServiceProvider" ascii //weight: 3
        $x_3_3 = "{11111-22222-10009-11112}" ascii //weight: 3
        $x_3_4 = "pUeAwDi7ERHX7K3xuf.Cg5bP5uCSMZg0q9JHB" ascii //weight: 3
        $x_3_5 = "MD5CryptoServiceProvider" ascii //weight: 3
        $x_3_6 = "ajECBeTY1gqIVAvJDqJ" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AN_2147818035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AN!MTB"
        threat_id = "2147818035"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 57 d4 02 fc c9 03 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 2d 00 00 00 0b 00 00 00 2b}  //weight: 1, accuracy: High
        $x_1_2 = "Convert" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "ResolveEventHandler" ascii //weight: 1
        $x_1_6 = "add_AssemblyResolve" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_RK_2147819153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.RK!MTB"
        threat_id = "2147819153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CredUIPromptForCredentials" ascii //weight: 1
        $x_1_2 = "USERNAME_TARGET_CREDENTIALS" ascii //weight: 1
        $x_1_3 = "CreateRunspace" ascii //weight: 1
        $x_1_4 = "Encoding" ascii //weight: 1
        $x_1_5 = "cG93ZXJzaGVsbC5leGUgLWV4ZWN1dGlvbnBvbGljeSBieXBhc3Mgc3RhcnQtc2xlZXAgNSA7IC5cMS50eHQNCg0KDQoNCg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AK_2147819239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AK!MTB"
        threat_id = "2147819239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 57 15 a2 09 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 30 00 00 00 07 00 00 00 07 00 00 00 1a}  //weight: 2, accuracy: High
        $x_2_2 = "loader/uploads" wide //weight: 2
        $x_2_3 = "Quickest" ascii //weight: 2
        $x_2_4 = "Retherm" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_NEF_2147822243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.NEF!MTB"
        threat_id = "2147822243"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {92 25 53 00 69 00 76 00 88 25 88 25 88 25 88 25 88 25 88 25 47 00 88 25 88 25 92 25 45 00 45 00 45 00 77 00 59 00 43}  //weight: 1, accuracy: High
        $x_1_2 = {78 00 45 00 4c 00 45 00 51 00 71 00 4f 00 61 00 66 00 34 00 45 00 45 00 77 00 38 00 52 00 44 00 79 00 32 00 36}  //weight: 1, accuracy: High
        $x_1_3 = {93 25 93 25 93 25 93 25 6a 00 4b 00 55 00 88 25 88 25 88 25 88 25 88 25 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_NEG_2147823575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.NEG!MTB"
        threat_id = "2147823575"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 09 11 05 03 11 05 09 28 5c 01 00 0a 28 5d 01 00 0a 11 05 17 d6 13 05 11 05 11 04 31 e2}  //weight: 1, accuracy: High
        $x_1_2 = "wendys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_F_2147830951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.F!MTB"
        threat_id = "2147830951"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ASODIHFISJHDFIKSJDHIF" ascii //weight: 1
        $x_1_2 = "loadasdfasdadsgoogle" ascii //weight: 1
        $x_1_3 = "WebClient" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "safdscvzxcv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SE_2147845903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SE!MTB"
        threat_id = "2147845903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7b 06 00 00 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 07 06 7b 07 00 00 04 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ARA_2147847476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ARA!MTB"
        threat_id = "2147847476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bhcwyjhww6cs9gzjjjcvyuplgp4pa8tl" ascii //weight: 2
        $x_2_2 = "Markdig.Resolver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ARA_2147847476_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ARA!MTB"
        threat_id = "2147847476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\StillerRolton.pdb" ascii //weight: 2
        $x_2_2 = "select * from logins" wide //weight: 2
        $x_2_3 = "password_value" wide //weight: 2
        $x_2_4 = "username_value" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ARA_2147847476_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ARA!MTB"
        threat_id = "2147847476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Users\\Ahmed\\Documents\\Visual Studio 2010\\Projects\\pla\\Bootmgr\\obj\\x86\\Debug\\Bootmgr.pdb" ascii //weight: 2
        $x_2_2 = "C:\\Boot\\Bootmgr.com" ascii //weight: 2
        $x_2_3 = "c:\\boot\\me.dll" ascii //weight: 2
        $x_2_4 = "log.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SL_2147849589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SL!MTB"
        threat_id = "2147849589"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 01 00 00 70 28 ?? ?? ?? 06 13 00 38 00 00 00 00 dd e0 ff ff ff 26 38 00 00 00 00 dd d8 ff ff ff}  //weight: 4, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AB_2147891670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AB!MTB"
        threat_id = "2147891670"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 25 1a 58 13 07 4b 11 07 25 1a 58 13 07 4b 5a 13 11 11 11 20 ?? ?? ?? ?? 33 2d 08 07 2d 07 11 07 1a 58 4b 2b 08 11 07 19 d3 1a 5a 58 4b e0 58 13 05 07 2d 05 11 07 4b 2b 08 11 07 18 d3 1a 5a 58 4b 18 64 13 06 2b 5a 11 11 2c 56 08 07 2d 07 11 07 1a 58 4b 2b 08 11 07 19 d3 1a 5a 58 4b e0 58 13 12 11 07 18 d3 1a 5a 58 4b 18 64 13 13 16 13 14 2b 28}  //weight: 1, accuracy: Low
        $x_1_2 = "QjAIgwSe" ascii //weight: 1
        $x_1_3 = "zkvVhsF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAQE_2147891800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAQE!MTB"
        threat_id = "2147891800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 25 18 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 03 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_NK_2147892368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.NK!MTB"
        threat_id = "2147892368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 02 6f 05 01 00 0a 6f ?? ?? ?? 0a 06 7e ?? ?? ?? 04 74 ?? ?? ?? 01 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_3 = "Debugger Detected" wide //weight: 1
        $x_1_4 = "IJnSxUfd7I" ascii //weight: 1
        $x_1_5 = "Runtame Brakor" ascii //weight: 1
        $x_1_6 = "typemdt" ascii //weight: 1
        $x_1_7 = "classthis" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AARP_2147892473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AARP!MTB"
        threat_id = "2147892473"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 8e 69 8d ?? 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7}  //weight: 3, accuracy: Low
        $x_1_2 = "UmVnQXNtLmV4ZQ==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_KAB_2147896394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.KAB!MTB"
        threat_id = "2147896394"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 0d 11 0d 11 08 16 11 08 8e 69 6f ?? 00 00 0a 13 0e 28 ?? 00 00 0a 11 0e 6f ?? 00 00 0a 80}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAWW_2147896913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAWW!MTB"
        threat_id = "2147896913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 1c 58 1c 59 1d 58 1d 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 1c 58 1c 59 1d 58 1d 59 91 61 28 ?? 00 00 0a 03 08 20 87 10 00 00 58 20 86 10 00 00 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31 9f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAXO_2147897514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAXO!MTB"
        threat_id = "2147897514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 8e 69 5d 17 59 17 58 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 1e 58 1f 09 58 1f 11 59 91 61 28 ?? 00 00 0a 03 08 20 89 10 00 00 58 20 88 10 00 00 59 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAXU_2147897623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAXU!MTB"
        threat_id = "2147897623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 5d 17 59 17 58 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 1e 58 1f 09 58 1f 11 59 91 61 28 ?? ?? 00 0a 03 08 20 89 10 00 00 58 20 88 10 00 00 59 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAYC_2147897793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAYC!MTB"
        threat_id = "2147897793"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 8e 69 5d 17 59 17 58 04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 1e 58 1f 09 58 1f 11 59 91 61 28 ?? ?? 00 0a 04 08 20 89 10 00 00 58 20 88 10 00 00 59 04 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAYD_2147897794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAYD!MTB"
        threat_id = "2147897794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 09 06 8e 69 5d 06 09 06 8e 69 5d 91 08 09 08 8e 69 5d 91 61 28 ?? 00 00 0a 06 09 17 58 06 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 09 17 58 0d 09 6a 06 8e 69 17 59 6a 07 17 58 6e 5a 31 bb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAYG_2147898096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAYG!MTB"
        threat_id = "2147898096"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 8e 69 5d 17 59 17 58 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 1e 58 1f 09 58 1f 11 59 91 61 28 ?? ?? 00 0a 02 08 20 89 10 00 00 58 20 88 10 00 00 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAZD_2147898702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAZD!MTB"
        threat_id = "2147898702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 09 06 07 09 59 17 59 91 9c 16}  //weight: 2, accuracy: High
        $x_2_2 = {06 07 09 59 17 59 11 04 9c 09 17 58 16 2d c2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAZF_2147898707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAZF!MTB"
        threat_id = "2147898707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 09 06 07 09 59 17 59 91 9c 06 07 09 59 17 59 11 04 9c 09 17 58 0d 09 16 2d d2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAZJ_2147898789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAZJ!MTB"
        threat_id = "2147898789"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 08 02 8e 69 5d 1c 59 1c 58 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 1e 58 1f 0a 58 1f 12 59 91 61 28 ?? 00 00 0a 02 08 20 89 10 00 00 58 20 88 10 00 00 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAZQ_2147898967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAZQ!MTB"
        threat_id = "2147898967"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 1c 59 1c 58 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 1e 58 1f 0a 58 1f 12 59 91 61 28 ?? 00 00 0a 03 08 20 89 10 00 00 58 20 88 10 00 00 59 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_NL_2147898969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.NL!MTB"
        threat_id = "2147898969"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "emmanouil_mastrantonakis_individualProject" ascii //weight: 1
        $x_1_2 = "@Password" ascii //weight: 1
        $x_1_3 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "emmanouilmastrantonakisindividualProject" ascii //weight: 1
        $x_1_6 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_7 = "<Password>k__BackingField" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "(FirstName, LastName, Role, Email, Phone, Username, Password)" ascii //weight: 1
        $x_1_10 = "TestFiles\\AllMessages.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_L_2147898976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.L!MTB"
        threat_id = "2147898976"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5d 91 03 04 03 8e b7 5d 91 61 02 04 17 58 02 8e b7 5d 91 59 ?? ?? ?? ?? ?? 58 20 00 01 00 00 5d d2}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAAB_2147899273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAAB!MTB"
        threat_id = "2147899273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 08 18 8c ?? 00 00 01 28 ?? 00 00 0a a5 ?? 00 00 01 6f ?? 00 00 0a 00 08 18 8c ?? 00 00 01 28 ?? 00 00 0a a5 ?? 00 00 01 6f ?? 00 00 0a 00 08 72 28 0c 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 0d 09 07 16 07 8e 69 6f ?? 00 00 0a 13 04}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAAF_2147899499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAAF!MTB"
        threat_id = "2147899499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0b 2b 13 00 06 07 02 03 07 91 07 28 ?? 00 00 06 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0c 08 2d e3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAAH_2147899653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAAH!MTB"
        threat_id = "2147899653"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 1f 20 59 1f 20 58 7e ?? ?? 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 61 28 ?? ?? 00 06 03 08 20 89 10 00 00 58 20 88 10 00 00 59 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAAM_2147899755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAAM!MTB"
        threat_id = "2147899755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 08 04 8e 69 5d 1f 0a 59 1f 0a 58 04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 61 28 ?? 00 00 0a 04 08 20 89 10 00 00 58 20 88 10 00 00 59 04 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AHAA_2147900230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AHAA!MTB"
        threat_id = "2147900230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 91 61 28 ?? 00 00 0a ?? 08 20 89 10 00 00 58 20 88 10 00 00 59 ?? 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_NN_2147900360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.NN!MTB"
        threat_id = "2147900360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 08 91 0d 08 1f 09 5d 13 04 03 11 04 9a 13 05 02 08 11 05 09 ?? ?? ?? ?? ?? b4 9c 08 17 d6 0c 08 07 31 dc}  //weight: 5, accuracy: Low
        $x_5_2 = {03 6e 60 02 ?? ?? ?? ?? ?? 66 03 66 d2 6e 60 5f b7 0a 2b 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AJAA_2147900401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AJAA!MTB"
        threat_id = "2147900401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 91 61 28 ?? ?? 00 06 ?? 08 20 89 10 00 00 58 20 88 10 00 00 59 ?? 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 1c 2d 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_BHAA_2147900990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.BHAA!MTB"
        threat_id = "2147900990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 65 2b 66 2b 6b 2b 73 1c 2c 45 18 2c f2 06 28 ?? 00 00 0a 0c}  //weight: 2, accuracy: Low
        $x_2_2 = {06 2b 98 28 ?? 00 00 2b 2b 93 28 ?? 00 00 2b 38 ?? ff ff ff 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_BIAA_2147900995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.BIAA!MTB"
        threat_id = "2147900995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 08 11 02 91 11 08 11 03 91 58 20 00 01 00 00 5d 13 07}  //weight: 2, accuracy: High
        $x_2_2 = {02 11 05 8f ?? 00 00 01 25 71 ?? 00 00 01 11 08 11 07 91 61 d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_MVT_2147901174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.MVT!MTB"
        threat_id = "2147901174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {12 11 11 14 28 3d 00 00 06 28 24 00 00 06 00}  //weight: 2, accuracy: High
        $x_1_2 = "Glukoza" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_MVD_2147901175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.MVD!MTB"
        threat_id = "2147901175"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "A310Logger" ascii //weight: 2
        $x_2_2 = "3b0e2d3d-3d66-42bb-8f9c-d6e188f359ae" ascii //weight: 2
        $x_1_3 = "key4.db" ascii //weight: 1
        $x_1_4 = "Login Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Stealer_SN_2147901245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SN!MTB"
        threat_id = "2147901245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 04 11 0a 02 11 0a 91 03 11 0a 03 6f 16 00 00 0a 5d 6f 17 00 00 0a 61 d2 9c 00 11 0a 17 58 13 0a 11 0a 02 8e 69 fe 04 13 0b 11 0b 3a ce ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SN_2147901245_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SN!MTB"
        threat_id = "2147901245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0d 6f 73 00 00 06 13 17 11 0d 6f 73 00 00 06 13 18 11 04 11 17 11 18 6f 40 00 00 0a 11 16 17 58 13 16 11 16 11 0c 3f d4 ff ff ff}  //weight: 2, accuracy: High
        $x_2_2 = "Weekend.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_CJAA_2147901549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.CJAA!MTB"
        threat_id = "2147901549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 91 61 28 ?? ?? 00 0a ?? 08 20 8a 10 00 00 58 20 89 10 00 00 59 ?? 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_MVB_2147901630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.MVB!MTB"
        threat_id = "2147901630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PassGrabber.exe" ascii //weight: 2
        $x_1_2 = "2ad711c8-fae6-40ef-83d5-a3f168d2b4e7" ascii //weight: 1
        $x_1_3 = "CalculateListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Stealer_N_2147901671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.N!MTB"
        threat_id = "2147901671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 1e 11 09 11 24 11 21 61 19 11 18 58 61 11 2f 61 d2 9c 20 1f}  //weight: 3, accuracy: High
        $x_3_2 = {11 08 02 58 20 96 ?? ?? ?? 11 00 58 11 01 61 61 11 0c 20 c5 ?? ?? ?? 11 00 61 11 01 59 5f 61 13 41}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_LA_2147901676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.LA!MTB"
        threat_id = "2147901676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Yandex\\YandexBrowser\\User Data\\Default\\Cookies" wide //weight: 2
        $x_2_2 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 2
        $x_2_3 = "\\Opera Software\\Opera Stable\\Login Data" wide //weight: 2
        $x_2_4 = "\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_LA_2147901676_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.LA!MTB"
        threat_id = "2147901676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 07 08 91 06 08 06 6f ?? ?? 00 0a 5d 6f ?? ?? 00 0a 61 d2 9c 00 08 17 58 0c 08 07 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_DBAA_2147902106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.DBAA!MTB"
        threat_id = "2147902106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 07 08 07 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 61}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_DJAA_2147902286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.DJAA!MTB"
        threat_id = "2147902286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8e 69 5d 1f 09 58 1f 0f 58 1f 18 59 91 07 08 07 8e 69 5d 1f 09 58 1f 0f 58 1f 18 59 91 61}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_DWAA_2147902608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.DWAA!MTB"
        threat_id = "2147902608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 07 08 07 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 61}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_DYAA_2147902697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.DYAA!MTB"
        threat_id = "2147902697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 0c 2b 0d 06 08 02 08 91 07 61 d2 9c 08 17 58 0c 08 02 8e 69 32 ed}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SGA_2147902865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SGA!MTB"
        threat_id = "2147902865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "module.teleg" ascii //weight: 1
        $x_1_2 = "Exodus.wallet" wide //weight: 1
        $x_1_3 = "vh428.timeweb.ru/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SGC_2147902866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SGC!MTB"
        threat_id = "2147902866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%temp%\\GetAdmin.vbs" ascii //weight: 1
        $x_1_2 = "start /B call OBF20x-stealer.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SG_2147902873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SG!MTB"
        threat_id = "2147902873"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileZilla\\recentservers.xml" wide //weight: 1
        $x_1_2 = "www.eziriz.com" wide //weight: 1
        $x_1_3 = "EmbeddedSQLiteDemo.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_MVE_2147903177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.MVE!MTB"
        threat_id = "2147903177"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "INZStealer.exe" ascii //weight: 1
        $x_1_2 = "Passwords" ascii //weight: 1
        $x_1_3 = "Discord" ascii //weight: 1
        $x_1_4 = "Login Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_FSAA_2147903480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.FSAA!MTB"
        threat_id = "2147903480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 07 6f ?? 00 00 0a 00 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 00 09 05 6f ?? 00 00 0a 00 09 0e 04 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_GGAA_2147904013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.GGAA!MTB"
        threat_id = "2147904013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 91 61 02 08 20 ?? 10 00 00 58 20 ?? 10 00 00 59 02 8e 69 5d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_GVAA_2147904498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.GVAA!MTB"
        threat_id = "2147904498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 10 00 00 00 fe 0e 02 00 fe 0c 05 00 fe 0c 04 00 fe 0c 18 00 6f ?? 00 00 0a 7e ?? 00 00 04 29 ?? 00 00 11 fe 0c 03 00 fe 0c 18 00 6f ?? 00 00 0a 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SGD_2147904864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SGD!MTB"
        threat_id = "2147904864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TeleSteal.Renci.SshNet.dll" ascii //weight: 1
        $x_1_2 = "\\TeleSteal.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SGE_2147905605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SGE!MTB"
        threat_id = "2147905605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$5e918ab3-19d4-47c4-b25e-b985b98674a5" ascii //weight: 1
        $x_1_2 = "lunaraccounts.json" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_IJAA_2147905618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.IJAA!MTB"
        threat_id = "2147905618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 8e 69 5d 7e ?? ?? 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? 00 06 03 08 1d 58 1c 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ITAA_2147905881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ITAA!MTB"
        threat_id = "2147905881"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 01 91 11 05 11 02 91 58 20 00 01 00 00 5d 13 13}  //weight: 5, accuracy: High
        $x_5_2 = {03 11 11 8f ?? 00 00 01 25 71 ?? 00 00 01 11 05 11 13 6f ?? 00 00 0a a5 ?? 00 00 01 61 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SDF_2147906441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SDF!MTB"
        threat_id = "2147906441"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0b 07 07 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 04 16 04 8e 69 6f ?? ?? ?? 0a 10 02 04}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SPCC_2147906761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SPCC!MTB"
        threat_id = "2147906761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 8e 69 16 30 06 73 ?? ?? ?? 0a 7a 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 03 16 03 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_MVG_2147907302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.MVG!MTB"
        threat_id = "2147907302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EmbeddedSQLiteDemo.exe" ascii //weight: 1
        $x_1_2 = "biostar" ascii //weight: 1
        $x_1_3 = "vacuum_db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SPCO_2147908222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SPCO!MTB"
        threat_id = "2147908222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 11 05 16 73 ?? ?? ?? 0a 13 08 11 08 11 06 6f ?? ?? ?? 0a 11 06 6f ?? ?? ?? 0a 0b dd 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_MVF_2147908401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.MVF!MTB"
        threat_id = "2147908401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Cinoshi" ascii //weight: 2
        $x_2_2 = "CockyGrabber" ascii //weight: 2
        $x_2_3 = "CC_NumberDecrypted" ascii //weight: 2
        $x_1_4 = "GetBookmarks" ascii //weight: 1
        $x_1_5 = "moz_cookies" wide //weight: 1
        $x_1_6 = "GetLoginsBy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Stealer_MU_2147908402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.MU!MTB"
        threat_id = "2147908402"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 65 00 00 0a 7e ea 00 00 04 07 06 6f 66 00 00 0a 28 67 00 00 0a 13 06 28 65 00 00 0a 11 06 16 11 06 8e 69 6f 66 00 00 0a 28 68 00 00 0a 13 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SPGC_2147909284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SPGC!MTB"
        threat_id = "2147909284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {dc 07 18 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 0c 08 06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_NB_2147909514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.NB!MTB"
        threat_id = "2147909514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Switch-Stealer" ascii //weight: 2
        $x_2_2 = "YouTube-main Delta v92 roll#1" ascii //weight: 2
        $x_2_3 = "AppData\\Local\\Temp\\cfg.exe" ascii //weight: 2
        $x_2_4 = "DownloadString" ascii //weight: 2
        $x_1_5 = "set_StartupUri" ascii //weight: 1
        $x_1_6 = "DownloadFileAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SGG_2147910060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SGG!MTB"
        threat_id = "2147910060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TelegramStealer.exe" ascii //weight: 1
        $x_1_2 = "KillTelegram" ascii //weight: 1
        $x_1_3 = "api.telegram.org/bot" wide //weight: 1
        $x_1_4 = "//t.me/SamsExploit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SSXP_2147910175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SSXP!MTB"
        threat_id = "2147910175"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 30 06 73 ?? ?? ?? 0a 7a 03 28 ?? ?? ?? 0a 0a 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 06 16 06 8e 69}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SO_2147911839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SO!MTB"
        threat_id = "2147911839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {14 0a 73 01 00 00 0a 72 01 00 00 70 28 02 00 00 0a 0a 02 7b 01 00 00 04 06 7d 02 00 00 04 dd 06 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SPXF_2147911934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SPXF!MTB"
        threat_id = "2147911934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 10 00 00 1f 40 28 ?? ?? ?? 06 0d 07 16 08 07 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SGI_2147912946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SGI!MTB"
        threat_id = "2147912946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 e6 05 00 70 28 92 00 00 0a 28 93 00 00 0a 72 20 06 00 70 28 92 00 00 0a 20 00 01 00 00 14 14 17 8d 13 00 00 01 25 16 09 6f 94 00 00 0a a2 6f 95 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_MG_2147913112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.MG!MTB"
        threat_id = "2147913112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rcHack" ascii //weight: 1
        $x_1_2 = "DisableRealtimeMonitoring" ascii //weight: 1
        $x_1_3 = "Remaining time" wide //weight: 1
        $x_1_4 = "DiscordCommand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAW_2147916558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAW!MTB"
        threat_id = "2147916558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\\\Cookies" wide //weight: 2
        $x_2_2 = "AppData\\Local\\Google\\Chrome\\User Data\\Default\\\\Login Data" wide //weight: 2
        $x_2_3 = "AppData\\Roaming\\Telegram Desktop\\tdata\\\\key_datas" wide //weight: 2
        $x_2_4 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\\resume safarzadeh.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_LLN_2147919112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.LLN!MTB"
        threat_id = "2147919112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 13 1f 16 13 20 2b 43 00 02 11 20 02 11 20 91 66 d2 9c 02 11 20 8f 21 00 00 01 25 71 21 00 00 01 1f 64 58 d2 81 21 00 00 01 02 11 20 8f 21 00 00 01 25 71 21 00 00 01 20 92 00 00 00 59 d2 81 21 00 00 01 00 11 20 17 58 13 20 11 20 02 8e 69 fe 04 13 21 11 21 2d b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_LAS_2147920103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.LAS!MTB"
        threat_id = "2147920103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f ab 00 00 0a 06 04 8c 5c 00 00 01 6f ab 00 00 0a 06 05 8c 58 00 00 01 6f ?? ?? ?? 0a 7e 54 00 00 04 1f 12 28 9e 00 00 06 6f ?? ?? ?? 0a 14 06 6f ?? ?? ?? 0a 6f a8 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_PAFO_2147920356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.PAFO!MTB"
        threat_id = "2147920356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1e 63 d1 13 14 11 11 11 0a 91 13 20 11 11 11 0a 11 20 11 26 61 11 1c 19 58 61 11 31 61 d2 9c 11 20 13 1c 17 11 0a 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_PAFP_2147920432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.PAFP!MTB"
        threat_id = "2147920432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1e 63 d1 13 14 11 11 11 08 91 13 25 11 11 11 08 11 25 11 22 61 19 11 1b 58 61 11 30 61 d2 9c 11 08 17 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AYA_2147921623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AYA!MTB"
        threat_id = "2147921623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 0c 04 00 00 fe 0c 31 00 20 ff ff 1f 00 5f 5a fe 0c 31 00 1f 15 64 58 fe 0e 31 00 20 09 10 01 00 fe 0c 31 00 5a fe 0c 26 00 58 fe 0e 31 00}  //weight: 2, accuracy: High
        $x_1_2 = "Debugger Detected" wide //weight: 1
        $x_1_3 = "$2eeebf43-1073-4312-9d8e-e2e674687f72" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_WXAA_2147921694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.WXAA!MTB"
        threat_id = "2147921694"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 18 6f ?? 00 00 0a 06 28 ?? 00 00 06 6f ?? 00 00 0a 06 28 ?? 00 00 06 6f ?? 00 00 0a 73 ?? 00 00 0a 0b 07 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0d de 1e}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_XTAA_2147921706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.XTAA!MTB"
        threat_id = "2147921706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {fe 0c 0c 00 fe 0c 0b 00 fe 0c 0c 00 fe 0c 0b 00 91 fe 0c 11 00 fe 0c 0b 00 fe 0c 11 00 8e 69 5d 91 61 d2 9c fe 0c 0b 00 20 ea f1 00 00 20 eb f1 00 00 61 58 fe 0e 0b 00}  //weight: 3, accuracy: High
        $x_2_2 = {20 1d 53 ff ff 20 e4 ac 00 00 58 8d 10 00 00 01 fe 0e 00 00 fe 0c 00 00 20 00 00 00 00 20 0f 71 d7 13 20 17 da 00 00 61 20 22 38 ff ff 20 fd c7 00 00 58 5f 62 20 aa 58 ff ff 20 56 a7 00 00 58 20 bf 36 ff ff 20 61 c9 00 00 58 20 70 1b d7 13 20 68 b0 00 00 61 59 20 1f 00 00 00 5f 64 60 fe 09 00 00 a2 fe 0c 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SWH_2147921864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SWH!MTB"
        threat_id = "2147921864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 b8 05 00 06 28 b7 05 00 06 0d 28 ?? ?? ?? 0a 28 b9 05 00 06 28 b7 05 00 06 28 15 00 00 0a 13 04 73 ?? ?? ?? 0a 13 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_YCAA_2147922221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.YCAA!MTB"
        threat_id = "2147922221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 06 6f ?? 00 00 0a 25 07 6f ?? 00 00 0a 0c 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "EY1hPDrMW" wide //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AYB_2147922978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AYB!MTB"
        threat_id = "2147922978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 18 6a 11 15 6e 5a 6d 13 16 11 16 6e 11 1a 6a 61 69 13 18 11 19 6e 11 1a 6a 61 69 13 1a 08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "$375c5eff-0650-4301-85ef-382cfefa9adf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AYC_2147922979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AYC!MTB"
        threat_id = "2147922979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 30 11 30 1f 19 62 61 13 30 11 30 11 30 1f 1b 64 61 13 30 11 39 20 48 3c f0 25 5a 20 05 c9 1d 02 61}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AYD_2147922980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AYD!MTB"
        threat_id = "2147922980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 03 17 8d 06 00 00 01 25 16 09 20 bf 24 0a 00 d6 8c 4c 00 00 01 a2 14 28 6c 00 00 0a 28 6d 00 00 0a 6f 6e 00 00 0a 00 09 17 d6 0d 09 08 31 d0}  //weight: 2, accuracy: High
        $x_1_2 = "DebuggerHidden" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ZCAA_2147923184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ZCAA!MTB"
        threat_id = "2147923184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 03 04 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c de 14}  //weight: 3, accuracy: Low
        $x_2_2 = {11 07 59 13 08 11 08 8d 2b 00 00 01 13 09 16 13 0d 2b 12 11 09 11 0d 07 11 07 11 0d 58 91 9c 11 0d 17 58 13 0d 11 0d 11 08 32 e8}  //weight: 2, accuracy: High
        $x_2_3 = {11 0b 2c 0a 11 04 11 0a 6f ?? 00 00 0a 26 11 0a 17 58 13 0a 11 0a 11 05 11 06 59 31 bd}  //weight: 2, accuracy: Low
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ABBA_2147924090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ABBA!MTB"
        threat_id = "2147924090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 08 16 07 16 1f 10 28 ?? 01 00 06 7e ?? 00 00 04 08 16 07 1f 0f 1f 10 28 ?? 01 00 06 7e ?? 00 00 04 06 07 28 ?? 01 00 06 7e ?? 00 00 04 06 18 28 ?? 01 00 06 7e ?? 00 00 04 06 1b 28 ?? 01 00 06 7e ?? 01 00 04 06 28 ?? 01 00 06 0d 7e ?? 01 00 04 09 05 16 05 8e 69 28 ?? 01 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ATCA_2147925763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ATCA!MTB"
        threat_id = "2147925763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 7e ?? 01 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 01 00 06 03 08 1e 58 1d 59 03 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_PAFN_2147925989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.PAFN!MTB"
        threat_id = "2147925989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 d1 13 12 11 ?? 11 ?? 91 13 ?? 11 ?? 11 ?? 11 ?? 11 ?? 61 11 1e 19 58 61 11 32 61 d2 9c 17 11 0a 58 13 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AEDA_2147926111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AEDA!MTB"
        threat_id = "2147926111"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 16 7e 05 00 00 04 8e 69 6f ?? 00 00 0a 0b 2b 00 07 2a}  //weight: 3, accuracy: Low
        $x_3_2 = {0a 00 7e 01 00 00 04 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 3, accuracy: Low
        $x_2_3 = "=====M============a==============i=============n=========" wide //weight: 2
        $x_1_4 = "Pixie dust" wide //weight: 1
        $x_1_5 = "Moonflower petals" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_NIT_2147926209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.NIT!MTB"
        threat_id = "2147926209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies" wide //weight: 2
        $x_2_2 = "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 2
        $x_2_3 = "AppData\\Roaming\\Telegram Desktop\\tdata\\key_datas" wide //weight: 2
        $x_1_4 = "Tel.zip" wide //weight: 1
        $x_1_5 = "ree.bat" wide //weight: 1
        $x_1_6 = "CreateAndRunRegistryBackupScript" ascii //weight: 1
        $x_1_7 = "CreateAndExecuteStartupScript" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_NITA_2147926210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.NITA!MTB"
        threat_id = "2147926210"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 8e 69 8d 03 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 06 2a}  //weight: 2, accuracy: High
        $x_1_2 = "GetClipboardText" ascii //weight: 1
        $x_1_3 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_NITA_2147926210_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.NITA!MTB"
        threat_id = "2147926210"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DecryptBrowsers" ascii //weight: 2
        $x_2_2 = "GetProcessesByName" ascii //weight: 2
        $x_2_3 = "Monero" wide //weight: 2
        $x_2_4 = "LitecoinCore" wide //weight: 2
        $x_1_5 = "Ethereum" wide //weight: 1
        $x_1_6 = "Passwords" wide //weight: 1
        $x_1_7 = "get_SandBoxie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Stealer_NITA_2147926210_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.NITA!MTB"
        threat_id = "2147926210"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 5a 12 01 28 ?? 00 00 0a 0c 12 02 28 ?? 00 00 0a 0d 7e 01 00 00 04 12 02 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 09 28 ?? 00 00 0a 2c 2f 12 02 28 ?? 00 00 0a 72 01 00 00 70 28 ?? 00 00 0a 2c 0f 09 11 04 7e 07 00 00 04 28 ?? 00 00 06 2b 0d 09 11 04 7e 06 00 00 04 28 ?? 00 00 06 12 01 28 ?? 00 00 0a 2d 9d}  //weight: 2, accuracy: Low
        $x_1_2 = {72 17 00 00 70 6f ?? 00 00 0a 17 58 6f ?? 00 00 0a 13 06 02 11 05 28 ?? 00 00 0a 13 07 11 07 8e 2c 1e 11 07 16 9a 11 06 28 ?? 00 00 0a 0c 03 11 07 16 9a 28 ?? 00 00 0a 11 06 28 ?? 00 00 0a 0d 09 28 ?? 00 00 0a 13 04 11 04 28 ?? 00 00 0a 2d 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AJEA_2147926954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AJEA!MTB"
        threat_id = "2147926954"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 74 6e 00 00 01 6f ?? 00 00 0a 13 0c 11 0c 74 6f 00 00 01 02 16 02 8e 69 6f ?? 00 00 0a 0a dd}  //weight: 3, accuracy: Low
        $x_2_2 = {04 13 07 16 13 08 1a 13 11 2b c0 11 07 74 0b 00 00 1b 11 08 9a 13 09 07 75 0c 00 00 1b 11 09 75 4c 00 00 01 1f 10 28 ?? 00 00 0a 6f 6d 00 00 0a}  //weight: 2, accuracy: Low
        $x_2_3 = {11 08 11 07 74 0b 00 00 1b 8e 69 fe 04 13 0a 11 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_PAFU_2147927898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.PAFU!MTB"
        threat_id = "2147927898"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 16 0c 38 ?? ?? ?? ?? 06 07 08 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 08 18 58 0c 08 07 6f ?? ?? ?? ?? 32 de 06 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 02 06 28 ?? ?? ?? ?? 0b 14 0c 07 39 11 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {20 e8 03 00 00 28 ?? ?? ?? ?? 06 17 58 0a 06 1b 32 ee}  //weight: 2, accuracy: Low
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_NITs_2147928291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.NITs!MTB"
        threat_id = "2147928291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 2
        $x_2_2 = "\\Opera Software\\Opera Stable\\Login Data" wide //weight: 2
        $x_2_3 = "\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide //weight: 2
        $x_1_4 = "\\Google\\Chrome\\User Data\\Default\\Cookies" wide //weight: 1
        $x_1_5 = "Stealer" wide //weight: 1
        $x_1_6 = "screen.jpg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AHHA_2147929013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AHHA!MTB"
        threat_id = "2147929013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {03 11 0f 1f 10 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 03 11 0f 1e 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 03 11 0f 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 11 06 11 0f 6a 61 13 06 06 11 06 58 0a}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 12 08 28 ?? 00 00 0a 9c 25 17 12 08 28 ?? 00 00 0a 9c 25 18 12 08 28 ?? 00 00 0a 9c 13 10 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SOG_2147929677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SOG!MTB"
        threat_id = "2147929677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 00 00 70 0c 72 ?? ?? ?? 70 0d 72 5a 01 00 70 13 04 09 72 9a 01 00 70 28 15 00 00 0a 6f 16 00 00 0a 6f 17 00 00 0a 0d 09 28 18 00 00 0a 74 13 00 00 01 13 05 72 b0 01 00 70 13 06 11 05 72 e8 01 00 70 6f 19 00 00 0a 00 72 f0 01 00 70 13 07 72 ?? ?? ?? 70 13 08 11 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ACJA_2147931166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ACJA!MTB"
        threat_id = "2147931166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 06 11 04 6f ?? 00 00 0a 00 00 de 0b 09 2c 07 09 6f ?? 00 00 0a 00 dc 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 08 13 05 2b 00 11 05 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_EM_2147931327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.EM!MTB"
        threat_id = "2147931327"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ocean-ac_ProcessedByFody" ascii //weight: 1
        $x_1_2 = "Ocean-ac.pdb" ascii //weight: 1
        $x_1_3 = "Taskkill Executed" ascii //weight: 1
        $x_1_4 = "keyauth.win" ascii //weight: 1
        $x_1_5 = "React Scanner - Cheat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AX_2147932585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AX!MTB"
        threat_id = "2147932585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 2
        $x_2_2 = "Google\\Chrome\\User Data\\Local State" wide //weight: 2
        $x_2_3 = "Google\\Chrome\\User Data\\Default\\Network\\Cookies" wide //weight: 2
        $x_2_4 = "Google\\Chrome\\User Data\\Default\\History" wide //weight: 2
        $x_2_5 = "Google\\Chrome\\User Data\\Default\\Web Data" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_STA_2147934109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.STA!MTB"
        threat_id = "2147934109"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 04 00 00 06 0a de 03 26 de 00 06 2c f1 06 28 05 00 00 06 0b 07 14 28 01 00 00 0a 2c 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ACMA_2147934151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ACMA!MTB"
        threat_id = "2147934151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 1a 58 4a 02 8e 69 5d 7e ?? ?? 00 04 02 06 1a 58 4a 02 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? 00 06 02 06 1a 58 4a 1d 58 1c 59 02 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SWI_2147935320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SWI!MTB"
        threat_id = "2147935320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 72 1a 0a 00 70 28 87 00 00 0a 09 72 ?? ?? ?? 70 6f 4b 01 00 0a 28 4c 01 00 0a 11 04 72 88 0a 00 70 28 87 00 00 0a 09 72 ?? ?? ?? 70 6f 4b 01 00 0a 28 4c 01 00 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_EAET_2147935747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.EAET!MTB"
        threat_id = "2147935747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 07 a3 05 00 00 01 0c 08 6f 16 00 00 0a 03 28 17 00 00 0a 39 02 00 00 00 08 2a 07 17 58 0b 07 06 8e 69 32 db}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_WRT_2147939018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.WRT!MTB"
        threat_id = "2147939018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 7b 72 01 00 04 7b 6f 01 00 04 02 7b 71 01 00 04 03 6f ?? 01 00 0a 0a 02 7b 72 01 00 04 7b 6c 01 00 04 02 7b 72 01 00 04 7b 6b 01 00 04 6f ?? 01 00 0a 59 0b 07 19 fe 04 16 fe 01 0c 08 2c 39 00 02 7b 72 01 00 04 7b 6b 01 00 04 19 8d a1 00 00 01 25 16 12 00 28 1c 01 00 0a 9c 25 17 12 00 28 1d 01 00 0a 9c 25 18 12 00 28 ?? 01 00 0a 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_EACC_2147939535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.EACC!MTB"
        threat_id = "2147939535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 11 04 9a 13 05 11 05 73 89 01 00 0a 6f 94 01 00 0a 13 06 11 06 6f 47 00 00 0a 1f 10 33 13 06 11 06 28 da 00 00 0a 13 07 11 05 11 07 28 5e 04 00 06 11 04 17 58 13 04 11 04 09 8e 69 32 c1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_VGT_2147939745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.VGT!MTB"
        threat_id = "2147939745"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 72 47 00 00 70 28 0c 00 00 0a 0b 73 0d 00 00 0a 0c 73 0e 00 00 0a 0d 09 08 06 07 6f ?? 00 00 0a 17 73 10 00 00 0a 13 04 11 04 03 16 03 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 dd 29 00 00 00 11 04 39 07 00 00 00 11 04 6f ?? 00 00 0a dc 09 39 06 00 00 00 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_BAA_2147940152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.BAA!MTB"
        threat_id = "2147940152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 06 02 06 91 03 61 d2 9c 06 17 58 0a 06 02 8e 69 32 ed 02 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_MGH_2147940532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.MGH!MTB"
        threat_id = "2147940532"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 13 20 30 01 00 00 91 2b ef 03 19 8d 05 00 00 01 25 16 12 07 20 a4 00 00 00 20 8e 00 00 00 28 ?? 00 00 06 9c 25 17 12 07 20 76 02 00 00 20 5d 02 00 00 28 ?? 00 00 06 9c 25 18 12 07 20 de 03 00 00 20 f2 03 00 00 28 ?? 00 00 06 9c 6f 62 00 00 0a 18 13 12 38 8f fe ff ff 20 ee 00 00 00 20 da 00 00 00 28 ?? 00 00 06 13 0c 12 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_BAB_2147940672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.BAB!MTB"
        threat_id = "2147940672"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 08 07 09 6f 2b 00 00 0a 03 09 03 6f 29 00 00 0a 5d 6f 2b 00 00 0a 61 d1 6f 2e 00 00 0a 26 00 09 17 58 0d 09 07 6f 29 00 00 0a fe 04 13 04 11 04 2d cd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SUG_2147940708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SUG!MTB"
        threat_id = "2147940708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 8d 1d 00 00 01 13 04 7e ?? ?? ?? 04 02 1a 58 11 04 16 08 28 d0 00 00 0a 28 23 00 00 0a 11 04 16 11 04 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_GFF_2147941402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.GFF!MTB"
        threat_id = "2147941402"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 1a 2f 0b 16 38 95 00 00 00 dd b5 00 00 00 72 fe 01 00 70 38 8c 00 00 00 38 91 00 00 00 1a 2c 5a 72 30 02 00 70 38 8a 00 00 00 0d 73 27 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 72 4a 02 00 70 13 06 11 05 06 16 06 8e 69 6f ?? 00 00 0a 13 07 11 06 11 07 03 28 ?? 00 00 06 de 0c 11 04 2c 07 11 04 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_SLGA_2147942190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.SLGA!MTB"
        threat_id = "2147942190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 28 0d 00 00 06 6f 02 00 00 0a 25 16 6f 03 00 00 0a 74 04 00 00 01 13 00 25 11 00 72 01 00 00 70 6f 04 00 00 0a 72 31 00 00 70 6f 05 00 00 0a 6f 02 00 00 0a 25 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ARVA_2147942443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ARVA!MTB"
        threat_id = "2147942443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 24 2b 26 16 2b 26 8e 69 2b 25 2b 2a 2b 2c 2b 31 2b 33 2b 38 11 06 72 ?? ?? 00 70 03 28 ?? 00 00 06 17 0b de 5c 11 05 2b d8 06 2b d7 06 2b d7 6f ?? 00 00 0a 2b d4 11 05 2b d2 6f ?? 00 00 0a 2b cd 11 04 2b cb 6f ?? 00 00 0a 2b c6 13 06 2b c4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ATVA_2147942523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ATVA!MTB"
        threat_id = "2147942523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 08 16 07 16 1f 10 28 ?? 01 00 06 7e ?? 01 00 04 08 16 07 1f 0f 1f 10 28 ?? 01 00 06 7e ?? 01 00 04 06 07 28 ?? 01 00 06 7e ?? 01 00 04 06 18 28 ?? 01 00 06 7e ?? 01 00 04 06 28 ?? 01 00 06 0d 7e ?? 01 00 04 09 02 16 02 8e 69 28 ?? 01 00 06 2a 73 7d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AGWA_2147943216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AGWA!MTB"
        threat_id = "2147943216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 c0 0f 00 00 28 ?? 00 00 0a 00 73 ?? 00 00 0a 0a 06 72 ?? 00 00 70 6f ?? 00 00 0a 0b 16 0c 2b 13 00 07 08 07 08 91 20 ?? ?? 00 00 59 d2 9c 08 17 58 0c 00 08 07 8e 69 fe 04 0d 09 2d e3 28 ?? 00 00 0a 07 6f ?? 00 00 0a 13 04 2b 00 11 04 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ABXA_2147944260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ABXA!MTB"
        threat_id = "2147944260"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 09 74 0a 00 00 1b 11 21 1f 64 5d 17 9c 11 08 74 ?? 00 00 1b 11 21 11 08 74 ?? 00 00 1b 8e 69 5d 11 21 20 00 01 00 00 5d d2 9c}  //weight: 3, accuracy: Low
        $x_2_2 = {19 8d 05 00 00 01 25 16 12 2b 20 6b 01 00 00 20 43 01 00 00 28 ?? 00 00 06 9c 25 17 12 2b 20 df 03 00 00 20 f6 03 00 00 28 ?? 00 00 06 9c 25 18 12 2b 20 e7 01 00 00 20 cd 01 00 00 28 ?? 00 00 06 9c 13 43 1f 2f 13 53}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AJXA_2147944421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AJXA!MTB"
        threat_id = "2147944421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 03 11 02 02 11 02 91 03 11 02 11 01 5d 6f ?? 00 00 0a 61 d2 9c 20}  //weight: 4, accuracy: Low
        $x_2_2 = {11 02 17 58 13 02 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AVWA_2147945639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AVWA!MTB"
        threat_id = "2147945639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 03 11 00 11 03 91 11 01 11 03 11 01 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20}  //weight: 5, accuracy: Low
        $x_2_2 = {11 00 8e 69 8d 03 00 00 01 13 04 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ZGR_2147945838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ZGR!MTB"
        threat_id = "2147945838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 03 04 6f ?? 00 00 0a 0a 12 01 fe ?? 13 00 00 02 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 0e 05 39 ?? 00 00 00 23 89 41 60 e5 d0 22 d3 3f 07 7b ?? 00 00 04 6c 5a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ACZA_2147945932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ACZA!MTB"
        threat_id = "2147945932"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 08 28 ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 6f ?? 00 00 0a 00 11 04 18 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 13 05 02}  //weight: 5, accuracy: Low
        $x_1_2 = "H584597B8G47D2HZC5KSF7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_STT_2147946308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.STT!MTB"
        threat_id = "2147946308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 14 0c 14 0d 14 13 04 14 13 05 00 28 ?? 00 00 0a 0d 09 14 fe 03 13 06 11 06 2c 27 09 07 6f ?? 00 00 0a 00 09 07 6f ?? 00 00 0a 00 09 6f ?? 01 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 00 00 0a 0a de 51 00 de 49}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AXAB_2147947622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AXAB!MTB"
        threat_id = "2147947622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 06 11 04 6f ?? 00 00 0a 13 05 23 00 00 00 00 00 00 f0 3f 11 04 6c 23 18 2d 44 54 fb 21 09 40 5a 18 02 6f ?? 00 00 0a 5a 6c 5b 28 ?? 00 00 0a 5b 13 06 23 0a d7 a3 70 3d 0a b7 3f 11 06 23 00 00 00 00 00 00 fc 3f 28 ?? 00 00 0a 5a 05 7b ?? 02 00 04 23 71 3d 0a d7 a3 70 e5 bf 28 ?? 00 00 0a 5a 13 07 23 00 00 00 00 00 00 04 c0 12 05 28 ?? 00 00 0a 6c}  //weight: 4, accuracy: Low
        $x_2_2 = {23 00 00 00 00 00 e0 6f 40 5b 23 bb bd d7 d9 df 7c db 3d 58 28 ?? 00 00 0a 5a 0e 04 7b ?? 02 00 04 58 13 08 23 00 00 00 00 00 00 04 c0 12 05 28 ?? 00 00 0a 6c 23 00 00 00 00 00 e0 6f 40 5b 23 bb bd d7 d9 df 7c db 3d 58 28 ?? 00 00 0a 5a 0e 04 7b ?? 02 00 04 58 13 09 23 00 00 00 00 00 00 04 c0 12 05 28 ?? 00 00 0a 6c 23 00 00 00 00 00 e0 6f 40 5b 23 bb bd d7 d9 df 7c db 3d 58 28 ?? 00 00 0a 5a 0e 04 7b ?? 02 00 04 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_EA_2147948419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.EA!MTB"
        threat_id = "2147948419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetWindowsProductKeyFromRegistry" ascii //weight: 2
        $x_2_2 = "DecodeProductKeyWin8AndUp" ascii //weight: 2
        $x_2_3 = "GetAllNetworkInterfaces" ascii //weight: 2
        $x_2_4 = "GetTokensFromDiscordApp" ascii //weight: 2
        $x_2_5 = "%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data" wide //weight: 2
        $x_2_6 = "$F2C565B6-E4F5-40B1-8C40-FB70CF5A2E6A" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ADCB_2147948849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ADCB!MTB"
        threat_id = "2147948849"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 26 0b 07 03 6f ?? 00 00 0a 07 04 6f ?? 00 00 0a 07 1f 0c 28 ?? 00 00 06 6f ?? 00 00 0a 07 1f 10 28 ?? 00 00 06 6f ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 1f 14 28 ?? 00 00 06 73 ?? 00 00 0a 0d 09 06 1f 18 28 ?? 00 00 06 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 04 de 45}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_ADDB_2147949700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.ADDB!MTB"
        threat_id = "2147949700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 06 11 07 1b 5d 1f 1f 5f 63 05 11 07 19 5d 1f 1f 5f 62 61 61 0b 00 11 07 17 58 13 07}  //weight: 5, accuracy: High
        $x_2_2 = {07 11 06 1f 1f 5a 06 1d 5f 58 61 0b 16 13 0a}  //weight: 2, accuracy: High
        $x_2_3 = {06 11 0a 11 06 58 07 19 5f 58 61 0a 02 11 06 11 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AODB_2147950308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AODB!MTB"
        threat_id = "2147950308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 a6 11 a6 73 ?? 00 00 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 16 28 ?? 00 00 0a 03 6f ?? 00 00 0a 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 11 a6 18 6f ?? 00 00 0a 11 a6 17 6f ?? 00 00 0a 11 a6 6f ?? 00 00 0a 02 16 02 8e b7 6f ?? 00 00 0a 13 05}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AAEB_2147950764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AAEB!MTB"
        threat_id = "2147950764"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {09 11 0b 20 83 00 00 00 5a 61 13 0c 16 13 0d}  //weight: 4, accuracy: High
        $x_3_2 = {11 0c 16 5f 13 11 11 11 19 5d 13 12 17 11 11 58 19 5d 13 13}  //weight: 3, accuracy: High
        $x_2_3 = {08 94 11 08 61 0e 05 1f 0f 5f 58 9e}  //weight: 2, accuracy: High
        $x_2_4 = {8e 69 5d 94 61 58 13 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_FZV_2147951187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.FZV!MTB"
        threat_id = "2147951187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 08 02 7b 17 00 00 04 02 7b 18 00 00 04 6f ?? 00 00 0a 13 0f 20 01 00 00 00 7e d2 00 00 04 7b 9b 00 00 04 39 0f 00 00 00 26 20 01 00 00 00 38 04 00 00 00 fe 0c 00 00}  //weight: 5, accuracy: Low
        $x_4_2 = {11 01 16 6a 6f ?? 00 00 0a 20 00 00 00 00 7e d2 00 00 04 7b a9 00 00 04 3a cc ff ff ff 26 20 00 00 00 00 38 c1 ff ff ff 00 11 06 6f ?? 00 00 0a 20 01 00 00 00 7e d2 00 00 04 7b 7e 00 00 04 39 a5 ff ff ff 26 20 01 00 00 00 38 9a ff ff ff}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealer_AWEB_2147952083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealer.AWEB!MTB"
        threat_id = "2147952083"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 03 61 04 61 8c ?? 00 00 01 2a}  //weight: 4, accuracy: Low
        $x_2_2 = {01 13 06 11 06 16 09 8c ?? 00 00 01 a2 11 06 14 28 ?? 00 00 0a 28 ?? 00 00 0a 02 17 8d ?? 00 00 01 13 07 11 07 16 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


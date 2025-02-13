rule VirTool_WinNT_Protmin_A_2147572410_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Protmin.gen!A"
        threat_id = "2147572410"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Protmin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\cnsmin.dll" ascii //weight: 2
        $x_2_2 = "Release2K\\CnsMinKPNTv2" ascii //weight: 2
        $x_2_3 = "System32\\cns.exe" ascii //weight: 2
        $x_2_4 = "System32\\cns.dll" ascii //weight: 2
        $x_3_5 = "software\\microsoft\\internet explorer\\urlsearchhooks" wide //weight: 3
        $x_3_6 = "registry\\machine\\software\\microsoft\\windows\\currentversion\\explorer\\shellexecutehooks" wide //weight: 3
        $x_2_7 = "ssprot.sys" ascii //weight: 2
        $x_2_8 = "GPigeon" ascii //weight: 2
        $x_2_9 = "vicelo" ascii //weight: 2
        $x_2_10 = "RSDSXY" ascii //weight: 2
        $x_2_11 = "keyspy" ascii //weight: 2
        $x_2_12 = "Adplus" ascii //weight: 2
        $x_3_13 = "\\Registry\\Machine\\Software\\CNREDIRECT" wide //weight: 3
        $x_3_14 = "\\system\\currentcontrolset\\services\\ssprot" ascii //weight: 3
        $x_3_15 = "\\Device\\CnsMinKP" wide //weight: 3
        $x_3_16 = "sDrivers\\CnsminKP.sys" wide //weight: 3
        $x_3_17 = "\\FileSystem\\Filters\\SSProt" wide //weight: 3
        $x_3_18 = "Drivers\\CnsminKP.sys" wide //weight: 3
        $x_4_19 = "BaseNamesObject\\CnsMinKP" wide //weight: 4
        $x_4_20 = "\\BaseNamedObjects\\CnsMinKPEvent" wide //weight: 4
        $x_15_21 = {8b 55 08 c7 06 70 00 00 00 c7 46 04 ?? ?? 01 00 c7 46 08 ?? ?? 01 00 c7 46 0c ?? ?? 01 00 c7 46 10 ?? ?? 01 00 c7 46 14 ?? ?? 01 00 c7 46 18 ?? ?? 01 00 c7 46 1c ?? ?? 01 00}  //weight: 15, accuracy: Low
        $x_12_22 = {89 72 28 a1 ?? ?? 01 00 83 c4 0c 83 f8 05 75 0b 83 3d}  //weight: 12, accuracy: Low
        $x_10_23 = {89 45 b8 89 45 c0 89 45 c8 89 45 d0 89 45 d8 89 45 e0}  //weight: 10, accuracy: High
        $x_5_24 = {68 49 66 73 20 33 db be 00 02 00 00 56 53 89 5d f8 88 5d ff ff 15 ?? ?? 01 00 8b f8 3b fb}  //weight: 5, accuracy: Low
        $x_5_25 = {68 49 66 73 20 be 00 02 00 00 33 db 56 53 89 5d fc ff 15 ?? ?? 01 00 8b f8 3b fb 0f}  //weight: 5, accuracy: Low
        $x_5_26 = {68 49 66 73 20 83 c7 38 b8 ?? ?? 01 00 6a 70 f3 ab 8b 3d ?? ?? 01 00 53 ff d7 8b f0}  //weight: 5, accuracy: Low
        $x_5_27 = {68 49 66 73 20 ab be 00 04 00 00 56 53 89 5d fc ab 89 5d f8 ff 15}  //weight: 5, accuracy: High
        $x_5_28 = {6a 1c 59 68 49 66 73 20 b8 ?? ?? 01 00 c7 46 34 ?? ?? 01 00 8d 7e 38 6a 70 f3 ab 8b 3d}  //weight: 5, accuracy: Low
        $x_5_29 = {53 68 76 72 44 00 68 00 04 00 00 53 53 53 68 ?? ?? 01 00 ff 15}  //weight: 5, accuracy: Low
        $x_4_30 = {8b 75 0c 0f b7 06 40 68 49 66 73 20 40 50 53 ff d7 a3 b0 90 01 00 0f b7 0e}  //weight: 4, accuracy: High
        $x_16_31 = {8b 45 08 c7 06 70 00 00 00 c7 46 04 ?? ?? 01 00 c7 46 08 ?? ?? 01 00 c7 46 0c ?? ?? 01 00 c7 46 10 ?? ?? 01 00 c7 46 14 ?? ?? 01 00 c7 46 18 ?? ?? 01 00 c7 46 1c ?? ?? 01 00 c7 46 20 ?? ?? 01 00 c7 46 24 ?? ?? 01 00 c7 46 28}  //weight: 16, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*) and 10 of ($x_2_*))) or
            ((6 of ($x_3_*) and 9 of ($x_2_*))) or
            ((7 of ($x_3_*) and 7 of ($x_2_*))) or
            ((8 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*) and 10 of ($x_2_*))) or
            ((1 of ($x_4_*) and 5 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_4_*) and 6 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_4_*) and 7 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 8 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 9 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_3_*) and 8 of ($x_2_*))) or
            ((2 of ($x_4_*) and 5 of ($x_3_*) and 6 of ($x_2_*))) or
            ((2 of ($x_4_*) and 6 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_4_*) and 7 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 8 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 10 of ($x_2_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_2_*))) or
            ((3 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_4_*) and 4 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_4_*) and 5 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_4_*) and 6 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_4_*) and 7 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*) and 8 of ($x_3_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_5_*) and 6 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 7 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 8 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 10 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 5 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 6 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 7 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 8 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 9 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 4 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 6 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*))) or
            ((2 of ($x_5_*) and 4 of ($x_3_*) and 7 of ($x_2_*))) or
            ((2 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 6 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 7 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 8 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 9 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 6 of ($x_3_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 7 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 5 of ($x_3_*))) or
            ((3 of ($x_5_*) and 10 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*) and 6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 7 of ($x_3_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_3_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 6 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_3_*))) or
            ((3 of ($x_5_*) and 3 of ($x_4_*) and 4 of ($x_2_*))) or
            ((3 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_3_*))) or
            ((4 of ($x_5_*) and 8 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_5_*) and 5 of ($x_3_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((4 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((4 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((4 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((4 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((5 of ($x_5_*) and 5 of ($x_2_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((5 of ($x_5_*) and 4 of ($x_3_*))) or
            ((5 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((5 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((5 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((5 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((5 of ($x_5_*) and 3 of ($x_4_*))) or
            ((6 of ($x_5_*) and 3 of ($x_2_*))) or
            ((6 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((6 of ($x_5_*) and 2 of ($x_3_*))) or
            ((6 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((6 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((6 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 6 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 7 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 8 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 6 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 7 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 9 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 4 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 6 of ($x_3_*))) or
            ((1 of ($x_10_*) and 3 of ($x_4_*) and 7 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_4_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_4_*) and 5 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_4_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*))) or
            ((1 of ($x_12_*) and 1 of ($x_3_*) and 10 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_12_*) and 4 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_12_*) and 5 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 6 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 7 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 8 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_4_*) and 10 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_4_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_4_*) and 6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_4_*) and 7 of ($x_3_*))) or
            ((1 of ($x_12_*) and 2 of ($x_4_*) and 8 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_4_*) and 5 of ($x_3_*))) or
            ((1 of ($x_12_*) and 3 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 9 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 6 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 3 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_12_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_12_*) and 3 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_12_*) and 4 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 4 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 4 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 5 of ($x_5_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 7 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 5 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 3 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((1 of ($x_15_*) and 10 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_4_*) and 8 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_4_*) and 5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_4_*) and 6 of ($x_3_*))) or
            ((1 of ($x_15_*) and 2 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_15_*) and 3 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 3 of ($x_4_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_4_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 3 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 2 of ($x_4_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_10_*))) or
            ((1 of ($x_16_*) and 10 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_16_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_16_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_16_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 7 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_4_*) and 8 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_4_*) and 5 of ($x_3_*))) or
            ((1 of ($x_16_*) and 2 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_16_*) and 3 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_16_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 3 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_16_*) and 2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_16_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_16_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_16_*) and 2 of ($x_5_*) and 3 of ($x_4_*))) or
            ((1 of ($x_16_*) and 3 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_16_*) and 3 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_16_*) and 4 of ($x_5_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 3 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 3 of ($x_4_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_16_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 4 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 3 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 2 of ($x_4_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 2 of ($x_5_*))) or
            ((1 of ($x_16_*) and 1 of ($x_12_*) and 1 of ($x_10_*))) or
            ((1 of ($x_16_*) and 1 of ($x_15_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_15_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_15_*) and 2 of ($x_3_*))) or
            ((1 of ($x_16_*) and 1 of ($x_15_*) and 1 of ($x_4_*))) or
            ((1 of ($x_16_*) and 1 of ($x_15_*) and 1 of ($x_5_*))) or
            ((1 of ($x_16_*) and 1 of ($x_15_*) and 1 of ($x_10_*))) or
            ((1 of ($x_16_*) and 1 of ($x_15_*) and 1 of ($x_12_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Protmin_B_2147572770_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Protmin.gen!B"
        threat_id = "2147572770"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Protmin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FileSystem\\ADProtCDO" wide //weight: 2
        $x_2_2 = "\\FileSystem\\Filters\\SSProt" wide //weight: 2
        $x_2_3 = "FileSystem\\FADCDO" wide //weight: 2
        $x_2_4 = "FileSystem\\Filters\\ADProt" wide //weight: 2
        $x_2_5 = "DosDevices\\C20060623" wide //weight: 2
        $x_2_6 = "ssprot.sys" ascii //weight: 2
        $x_2_7 = "Software\\360safe\\AntiBadware" ascii //weight: 2
        $x_5_8 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 c4 d0 53 56 57 89 65 e8 c6 45}  //weight: 5, accuracy: High
        $x_10_9 = {c6 45 cc 96 c6 45 cd bc c6 45 ce 87 c6 45 cf 8a c6 45 d0 b8 c6 45 d1 8c c6 45 d2 f9 c6 45 d3 8b c6 45 d4 ae c6 45 d5 8b c6 45 d6 00 c6 45 d8 00 33 c0}  //weight: 10, accuracy: High
        $x_10_10 = {c6 45 d0 e7 c6 45 d1 c8 c6 45 d2 e7 c6 45 d3 c8 c6 45 d4 f9 c6 45 d5 8b c6 45 d6 ae c6 45 d7 8b c6 45 d8 00 c6 45 dc 00 33 c0}  //weight: 10, accuracy: High
        $x_5_11 = {85 c0 75 02 eb 3c 8b 45 c0 33 d2 b9 02 00 00 00 f7 f1 85 d2 75 16 8b 55}  //weight: 5, accuracy: High
        $x_5_12 = {b8 bb 00 00 c0 eb 71 e8 e0 fc ff ff e8 7b fe ff ff 68 34 42 01 00 8d 45 f4 50 ff 15}  //weight: 5, accuracy: High
        $x_4_13 = {6a 01 6a 00 68 01 83 00 00 8d 45 f4 50 6a 00 8b 4d 08 51 ff 15}  //weight: 4, accuracy: High
        $x_7_14 = {ff 15 10 41 01 00 89 45 c4 83 7d c4 00 83}  //weight: 7, accuracy: High
        $x_10_15 = {c7 45 c8 18 00 00 00 c7 45 cc 00 00 00 00 c7 45 d4 40 02 00 00 8b 45 0c 89 45 d0}  //weight: 10, accuracy: High
        $x_9_16 = {c7 45 d8 18 00 00 00 c7 45 dc 00 00 00 00 c7 45 e4 40 02 00 00 8d 45 d0}  //weight: 9, accuracy: High
        $x_10_17 = {8b 45 0c 8b 48 18 8b 50 1c 8b 45 0c 8b 40 28 89 08 89 50 04 8b 4d}  //weight: 10, accuracy: High
        $x_15_18 = {c7 85 5c fd ff ff 18 00 00 00 c7 85 60 fd ff ff 00 00 00 00 c7 85 68 fd ff ff 40 02 00 00 8d 95 74 fd ff ff 89 95 64 fd ff ff c7 85 6c fd ff ff 00 00 00 00 c7}  //weight: 15, accuracy: High
        $x_10_19 = {68 3f 00 0f 00 8d 95 58 fd ff ff 52 ff 15 80 40 01 00 89 45 cc 83 7d cc 00 7c 1a 8b}  //weight: 10, accuracy: High
        $x_12_20 = {ff 15 70 40 01 00 e8 e2 f9 ff ff a3 bc 55 01 00 6a 00 68 90 14 01 00 e8 ff 17 00 00 6a 00 68 80 16 01 00 8b 45 08 50}  //weight: 12, accuracy: High
        $x_10_21 = {8b 55 cc 83 c2 01 89 55 cc 8b 45 dc 8b 4d cc 3b 48 18 73 68 8b 55 cc 8b 45 d8 0f bf 0c 50 89 4d c8 8b 55 e0 2b 55 e8 8b 45 c8 8b 4d d0 39 14 81 72 14 8b 55 e0 03 55 e4 2b 55 e8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*))) or
            ((1 of ($x_7_*) and 3 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_7_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_9_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_9_*) and 3 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_9_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 3 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 3 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_4_*) and 7 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 3 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 3 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 3 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 3 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 4 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_9_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((2 of ($x_10_*) and 1 of ($x_9_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*))) or
            ((3 of ($x_10_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_10_*) and 1 of ($x_7_*))) or
            ((3 of ($x_10_*) and 1 of ($x_9_*))) or
            ((4 of ($x_10_*))) or
            ((1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 3 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 3 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 7 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 3 of ($x_5_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 2 of ($x_5_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 7 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 3 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_5_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_9_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_5_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*))) or
            ((1 of ($x_12_*) and 2 of ($x_10_*) and 2 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_10_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_12_*) and 2 of ($x_10_*) and 1 of ($x_7_*))) or
            ((1 of ($x_12_*) and 2 of ($x_10_*) and 1 of ($x_9_*))) or
            ((1 of ($x_12_*) and 3 of ($x_10_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_7_*) and 7 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_7_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_15_*) and 1 of ($x_7_*) and 3 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_9_*) and 6 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_9_*) and 1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_9_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_9_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_15_*) and 1 of ($x_9_*) and 3 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_4_*))) or
            ((1 of ($x_15_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_4_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_4_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_4_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_9_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Protmin_C_2147593595_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Protmin.gen!C"
        threat_id = "2147593595"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Protmin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\CNNIC\\CdnClient\\InstallInfo" wide //weight: 5
        $x_5_2 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CdnProt" wide //weight: 5
        $x_5_3 = "\\Device\\CdnProt" wide //weight: 5
        $x_5_4 = "\\DosDevices\\CdnProt" wide //weight: 5
        $x_5_5 = {45 58 50 4c 4f 52 45 52 2e 45 58 45 [0-5] 4d 53 48 54 41 2e 45 58 45 [0-5] 52 55 4e 44 4c 4c 33 32 2e 45 58 45 [0-5] 45 58 50 4c 4f 52 45 52 2e 45 58 45}  //weight: 5, accuracy: Low
        $x_5_6 = {3b f7 74 37 ff 75 10 ff 15 [0-5] 80 7d 14 00 59 8d 46 08 50 ff 75 10 74 0e ff 15 [0-5] 59 85 c0 59 75 12 eb 0c}  //weight: 5, accuracy: Low
        $x_10_7 = {8d 3c 01 83 3c 01 83 c9 ff 33 c0 f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 80 7d 08 00 74 35 8d 7d c0 83 c9 ff 33 c0 f2 ae f7 d1 49 39 4d 0c 76 23 8d 7d c0 83 c9 ff f2 ae f7 d1 2b f9 8b c1 8b f7 8b e9 02 f3 a5 8b c8 83 e1 03 f3 a4 eb 02}  //weight: 10, accuracy: High
        $x_10_8 = {f2 ae f7 d1 83 c1 08 51 6a 01 ff [0-5] 8b f0 33 c0 3b f0 74 61 8b 7c 24 0c 53 50 50 50 bb [0-5] 50 53 89 3e ff 15 [0-5] c1 ef 02 81 e7 ff 00 00 00 8d 56 08 6a 00 53}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_5_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}


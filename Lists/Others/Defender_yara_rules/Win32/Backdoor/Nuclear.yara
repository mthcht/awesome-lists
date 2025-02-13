rule Backdoor_Win32_Nuclear_2147582343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nuclear"
        threat_id = "2147582343"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuclear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dllfile\\shell\\open\\command" ascii //weight: 1
        $x_1_2 = "%w\\NR" ascii //weight: 1
        $x_2_3 = "%all\\" ascii //weight: 2
        $x_1_4 = "ProgramFilesDir" ascii //weight: 1
        $x_10_5 = {55 8b ec 83 c4 f8 53 56 33 db 89 5d f8 89 4d fc 8b da 8b f0 8b 45 fc e8 [0-4] 33 c0 55 68 [0-4] 64 ff 30 64 89 20 8d 55 f8 8b 45 fc e8 [0-4] 8b 55 f8 8d 45 fc e8 [0-4] 8b 45 fc e8 [0-4] 50 56 e8 [0-4] 89 03 83 3b 00 0f 95 c0 8b d8 33 c0 5a 59 59 64 89 10 68 [0-4] 8d 45 f8 ba 02 00 00 00 e8 [0-4] c3}  //weight: 10, accuracy: Low
        $x_5_6 = {55 8b ec 81 c4 40 ff ff ff 53 56 57 8b da 89 45 fc 8b 45 fc e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 c7 85 40 ff ff ff 94 00 00 00 8d 85 40 ff ff ff 50 a1 ?? ?? fd 13 8b 00 ff d0 83 bd 50 ff ff ff 02 0f 85 87 00 00 00 8d 45 f8 50 6a 28 a1 ?? ?? fd 13 8b 00 ff d0 50 a1 ?? ?? fd 13 8b 00 ff d0 8d 45 e8 50 8b 45 fc e8}  //weight: 5, accuracy: Low
        $x_5_7 = {50 6a 00 a1 ?? ?? fd 13 8b 00 ff d0 85 c0 74 45 c7 45 e4 01 00 00 00 84 db 74 09 c7 45 f0 02 00 00 00 eb 05 33 c0 89 45 f0 33 c0 89 45 f4 8d 75 e4 8d 7d d4 a5 a5 a5 a5 8d 45 f4 50 8d 45 d4 50 6a 10 8d 45 e4 50 6a 00 8b 45 f8 50 a1 ?? ?? fd 13 8b 00 ff d0 8b 45 f8 50 a1 ?? ?? fd 13 8b 00 ff d0 33 c0 5a 59 59 64 89 10 68 ?? ?? fd 13 8d 45 fc e8 ?? ?? ?? ?? c3}  //weight: 5, accuracy: Low
        $x_1_8 = "KofcLo~ofoN" ascii //weight: 1
        $x_1_9 = "ffn$89fodxoa" ascii //weight: 1
        $x_1_10 = "nd}skx~UffobY" ascii //weight: 1
        $x_1_11 = "wsock32.dll ws2_32.dll mswsock.dll" ascii //weight: 1
        $x_1_12 = "ogc^ofcL~oY" ascii //weight: 1
        $x_1_13 = "Ksxe~ioxcNo~koxI" ascii //weight: 1
        $x_1_14 = "neG~oM" ascii //weight: 1
        $x_1_15 = "KsoAo~ofoNmoX" ascii //weight: 1
        $x_1_16 = "ofcLo~cx]" ascii //weight: 1
        $x_1_17 = "xo~fcLdec~zoirOnofndkbd_~oY" ascii //weight: 1
        $x_1_18 = "yoic|xoYd" ascii //weight: 1
        $x_1_19 = "KrOsoAdozEmoX" ascii //weight: 1
        $x_1_20 = "Kge~KndcLfkhefM" ascii //weight: 1
        $x_1_21 = "eyoXaieF" ascii //weight: 1
        $x_1_22 = "hcx~~KofcL~oY" ascii //weight: 1
        $x_1_23 = "KogkDofcLof" ascii //weight: 1
        $x_1_24 = "yomofc|cxZdoae^~y" ascii //weight: 1
        $x_1_25 = "KofndkBof" ascii //weight: 1
        $x_1_26 = "yyoiexZ~doxx" ascii //weight: 1
        $x_1_27 = "sxegoGyyoiexZo~cx]" ascii //weight: 1
        $x_1_28 = "iorOffobY" ascii //weight: 1
        $x_1_29 = "KofcLszeI" ascii //weight: 1
        $x_1_30 = "~xk~Y~oM" ascii //weight: 1
        $x_1_31 = "eyoXnkeF" ascii //weight: 1
        $x_1_32 = "soAoyefImoX" ascii //weight: 1
        $x_1_33 = "Ksxe~ioxcNy}endc]~oM" ascii //weight: 1
        $x_1_34 = "KrOdecyxo\\~oM" ascii //weight: 1
        $x_1_35 = "KrOsoAo~koxImoX" ascii //weight: 1
        $x_1_36 = "hcx~~KofcL~oM" ascii //weight: 1
        $x_1_37 = "XVdecyxo\\~doxx" ascii //weight: 1
        $x_1_38 = "iorOndcL" ascii //weight: 1
        $x_1_39 = "KyyoiexZo~koxI" ascii //weight: 1
        $x_1_40 = "eyoXndcL" ascii //weight: 1
        $x_1_41 = "ofcLdozE" ascii //weight: 1
        $x_1_42 = "~oY*o|c~iKV~leyexicGVOXK]^LEY" ascii //weight: 1
        $x_1_43 = "eyoXleopcY" ascii //weight: 1
        $x_1_44 = "ogc^ofcL~oM" ascii //weight: 1
        $x_1_45 = "sxkxhcFooxL" ascii //weight: 1
        $x_1_46 = "nkoxb^o~egoXo~koxI" ascii //weight: 1
        $x_1_47 = "doae^yyoiexZdozE" ascii //weight: 1
        $x_1_48 = "Kofhk~" ascii //weight: 1
        $x_1_49 = "ge~Ko~ofoNfkhefM" ascii //weight: 1
        $x_1_50 = "fk\\sxo" ascii //weight: 1
        $x_1_51 = "KreHomkyyoG" ascii //weight: 1
        $x_1_52 = "yyoiexZdozE" ascii //weight: 1
        $x_1_53 = "IVy}endc]V~leyexicGVOXK]^LEY" ascii //weight: 1
        $x_1_54 = "Kczgix~yf" ascii //weight: 1
        $x_1_55 = "rOieffKfk" ascii //weight: 1
        $x_1_56 = "fk\\~oYmoX" ascii //weight: 1
        $x_1_57 = "K}endc]ndcL" ascii //weight: 1
        $x_1_58 = "b~kZh" ascii //weight: 1
        $x_1_59 = "nCyyoiexZnkoxb^}endc]~oM" ascii //weight: 1
        $x_1_60 = "fk\\omofc|cxZz" ascii //weight: 1
        $x_1_61 = "KofcLo~koxI" ascii //weight: 1
        $x_1_62 = "ofndkBoyefI" ascii //weight: 1
        $x_1_63 = "KogkDb~kZmdeF~oM" ascii //weight: 1
        $x_1_64 = "KeldCz" ascii //weight: 1
        $x_1_65 = "Kszix~yf" ascii //weight: 1
        $x_1_66 = "Ksxe~ioxcNgo~ysY~oM" ascii //weight: 1
        $x_1_67 = "oyefIndcL" ascii //weight: 1
        $x_1_68 = "yyoiexZ~crO" ascii //weight: 1
        $x_1_69 = "K~kix~yf" ascii //weight: 1
        $x_1_70 = "KofcL~yxcLndcL" ascii //weight: 1
        $x_1_71 = "Kdszix~yf" ascii //weight: 1
        $x_1_72 = "eyoXooxL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 68 of ($x_1_*))) or
            ((1 of ($x_5_*) and 65 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 63 of ($x_1_*))) or
            ((2 of ($x_5_*) and 60 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 58 of ($x_1_*))) or
            ((1 of ($x_10_*) and 60 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 58 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 55 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 53 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 50 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 48 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Nuclear_B_2147597675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nuclear.gen!B"
        threat_id = "2147597675"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuclear"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%a\\NR" wide //weight: 1
        $x_10_2 = {68 a0 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 8b d8 53 e8 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 6a 00 53 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 82 00 00 00 53 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Nuclear_BD_2147602093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nuclear.BD"
        threat_id = "2147602093"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuclear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "155"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_10_2 = "TJustScan" ascii //weight: 10
        $x_10_3 = "TTCPTunnel4" ascii //weight: 10
        $x_10_4 = "Nuclear RAT WebServer" ascii //weight: 10
        $x_10_5 = "http://www.nuclearwinter.us" ascii //weight: 10
        $x_10_6 = "javascript:history.go(-1);" ascii //weight: 10
        $x_1_7 = "listen" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_10 = "InternetOpenA" ascii //weight: 1
        $x_1_11 = "InternetReadFile" ascii //weight: 1
        $x_1_12 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_13 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 5 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Nuclear_BF_2147604730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nuclear.BF"
        threat_id = "2147604730"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuclear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Nuclear RAT WebServer" ascii //weight: 5
        $x_1_2 = "[CTRL]" ascii //weight: 1
        $x_1_3 = "[TAB]" ascii //weight: 1
        $x_1_4 = "{Right Click}" ascii //weight: 1
        $x_1_5 = "{Middle Click}" ascii //weight: 1
        $x_1_6 = "?action=log&type=" ascii //weight: 1
        $x_1_7 = "&user=" ascii //weight: 1
        $x_1_8 = "~ Speed:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}


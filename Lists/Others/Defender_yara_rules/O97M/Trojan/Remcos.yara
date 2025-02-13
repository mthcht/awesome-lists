rule Trojan_O97M_Remcos_BIK_2147775384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Remcos.BIK!MTB"
        threat_id = "2147775384"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set amsl = GetObject(OskfZUWh())" ascii //weight: 1
        $x_1_2 = "amsl.Run \"P\" + mJJGM(fgfjhfgfg), 0" ascii //weight: 1
        $x_1_3 = "= mJJGM(\"B0A85DF40\" + fjjsdfhl() + j00ffdgdf() + tter7fdg0()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Remcos_BIK_2147775384_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Remcos.BIK!MTB"
        threat_id = "2147775384"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= sssssss(\"a\", eNYLSkLnCGGpsSH)" ascii //weight: 1
        $x_1_2 = "= Val(\"&H\" & (Mid$(DataIn, (2 * lonDataPtr) - 1, 2)))" ascii //weight: 1
        $x_1_3 = "= Asc(Mid$(CodeKey, ((lonDataPtr Mod Len(CodeKey)) + 1), 1))" ascii //weight: 1
        $x_1_4 = "= Shell(sssssss)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Remcos_PDA_2147830038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Remcos.PDA!MTB"
        threat_id = "2147830038"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "='eW.teN tc' + 'ejbO-weN(';$Ax1='olnwoD.)tnei' + 'lCb'; $c3=')''sbv.dapeton\\''+pmet:vne$,''sbv.tneilC detcetorP/ababila/kt.denik//:ptth''(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Remcos_RP_2147832548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Remcos.RP!MTB"
        threat_id = "2147832548"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//209.127.20.13/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_O97M_AgentTesla_PA_2147767779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.PA!MTB"
        threat_id = "2147767779"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pdas3 = \"t\" + \"a ht\"" ascii //weight: 1
        $x_1_2 = "Shell pkkkk" ascii //weight: 1
        $x_1_3 = "okffr = \"akdkasdoaksdddwid" ascii //weight: 1
        $x_1_4 = "kaskdk.hissssa" ascii //weight: 1
        $x_1_5 = "ko4d = \"tp://%748237%728748@j.mp/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RS_2147767796_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RS!MTB"
        threat_id = "2147767796"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pdas3 = \"t\" + \"a ht\"" ascii //weight: 1
        $x_1_2 = "Shell pkkkk" ascii //weight: 1
        $x_1_3 = {6f 6b 66 66 72 20 3d 20 22 61 6b [0-15] 64 64 77 69 64 22}  //weight: 1, accuracy: Low
        $x_1_4 = "kaskdk.hissssa" ascii //weight: 1
        $x_1_5 = "ko4d = \"tp://%748237%728748@j.mp/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_BK_2147768533_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.BK!MTB"
        threat_id = "2147768533"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p^i^N^g^.^e^X^E" ascii //weight: 1
        $x_1_2 = "^h^t^t^p^s^:^/^/^c^a^n^a^d^a^c^i^g^a^r^s^u^p^p^l^i^e^s^.^c^o^m^/^w^p^-^c^o^n^t^e^n^t^/^u^p^l^o^a^d^s^/^2^0^1^8^/^0^5^/^f^i^l^e^s^/^a^n^o^.^e^x^e" ascii //weight: 1
        $x_1_3 = "%TEMP%^\\^f^i^l^e^s^.^e^x^e" ascii //weight: 1
        $x_1_4 = "s^t^a^r^t^   ^   ^   %TEMP%^\\^f^i^l^e^s^.^e^x^e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_BK_2147768533_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.BK!MTB"
        threat_id = "2147768533"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "x = XORDecryption(\"as\", \"030E040401" ascii //weight: 1
        $x_1_2 = "Application.Wait (Now + TimeValue(\"0:00:05\"))" ascii //weight: 1
        $x_1_3 = "= Val(\"&H\" & (Mid$(DataIn, (2 * lonDataPtr) - 1, 2)))" ascii //weight: 1
        $x_1_4 = "= strDataOut + Chr(intXOrValue1 Xor intXOrValue2)" ascii //weight: 1
        $x_1_5 = "= Asc(Mid$(\"as\", ((lonDataPtr Mod Len(\"as\")) + 1), 1))" ascii //weight: 1
        $x_1_6 = "Shell (strDataOut)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVA_2147770388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVA!MTB"
        threat_id = "2147770388"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\"tp://1230912489%1230192309@j.mp/\"" ascii //weight: 2
        $x_2_2 = "\"tp://1230948%1230948@j.mp/\"" ascii //weight: 2
        $x_2_3 = "\"jdasdvjgasgvdbjhasdok\"" ascii //weight: 2
        $x_2_4 = "\"23bbsdajs821\"" ascii //weight: 2
        $x_1_5 = "= \"hta\"\" ht\"" ascii //weight: 1
        $x_1_6 = "Shell (WINWORD + MsgBoxOl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_AgentTesla_RVA_2147770388_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVA!MTB"
        threat_id = "2147770388"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "callshell!(textfilestuffonly)endfunction" ascii //weight: 1
        $x_1_2 = "=opera.x+opera.y+textfileforyou.z+textfileforyou.d+hi.openmarket+hi.xxx+hi.k+hi.t" ascii //weight: 1
        $x_1_3 = "textfilestuff.mosuf.tagendfunction" ascii //weight: 1
        $x_1_4 = "auto_close()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_BPK_2147777682_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.BPK!MTB"
        threat_id = "2147777682"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "manpower1 = man1 + man2 + man3" ascii //weight: 1
        $x_1_2 = "Debug.Assert (VBA.Shell(manpower3))" ascii //weight: 1
        $x_1_3 = "man2 = icecream1.jack1.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_BPK_2147777682_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.BPK!MTB"
        threat_id = "2147777682"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell k.myvalue + k.myvalue2" ascii //weight: 1
        $x_1_2 = "t\" + \"t\" + \"p\" + \":\" + \"/\" + \"/\" + \"w\" + \"w\" + \"w\" + \".j.mp/asdaksdjqwoddaskdajk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_BPK_2147777682_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.BPK!MTB"
        threat_id = "2147777682"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \" H\" + D + D + L + \"://\" + K + T" ascii //weight: 1
        $x_1_2 = "pings = X + Y + Z + D + E + F" ascii //weight: 1
        $x_1_3 = "GetObject(\"new:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B\").EXEC pings" ascii //weight: 1
        $x_1_4 = "= \"asdimawxiwmawidwwdkiiwnawij\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVC_2147781969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVC!MTB"
        threat_id = "2147781969"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 65 74 45 6e 75 6d 4e 61 6d 65 20 3d 20 22 20 68 74 74 70 73 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 62 69 74 6c 79 2e 63 6f 6d 2f [0-20] 22 0d 0a 20 20 20 20 45 6e 64 20 53 65 6c 65 63 74}  //weight: 1, accuracy: Low
        $x_1_2 = "myvalue = GetObject(\"new:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B\")" ascii //weight: 1
        $x_1_3 = {62 6f 72 61 2e 20 5f 0d 0a 6d 79 76 61 6c 75 65 2e 20 5f 0d 0a 52 75 6e 20 6c 6f 72 61 32}  //weight: 1, accuracy: High
        $x_1_4 = "lora2 = NamakBora + lora" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVD_2147782182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVD!MTB"
        threat_id = "2147782182"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"m\" + \"s\" + \"h\" + \"t\" + \"a\"" ascii //weight: 1
        $x_1_2 = "\"https://www.bitly.com/asiajia" ascii //weight: 1
        $x_1_3 = "\"https://www.bitly.com/asahdjia" ascii //weight: 1
        $x_1_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 40 20 5f 0d 0a 4e 61 6d 61 6b 42 6f 72 61 20 5f 0d 0a 2c 20 5f 0d 0a 6c 6f 72 61 32}  //weight: 1, accuracy: High
        $x_1_5 = {53 74 72 52 65 76 65 72 73 65 20 5f 0d 0a 28 22 30 30 30 30 34 35 33 35 35 34 34 34 2d 45 39 34 41 2d 45 43 31 31 2d 39 37 32 43 2d 30 32 36 39 30 37 33 31 3a 77 65 6e 22 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVF_2147782821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVF!MTB"
        threat_id = "2147782821"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "P_public + \"shta \" + StrReverse(\".www//:ptth\") + \"bitly.com/asdhjwqdoqiwodma\"" ascii //weight: 1
        $x_1_2 = "P_public = \"m\"" ascii //weight: 1
        $x_1_3 = "obj2.RestartCall obj.n_name" ascii //weight: 1
        $x_1_4 = "Sub auto_close()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVG_2147782839_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVG!MTB"
        threat_id = "2147782839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "createobject(mic)setw0bnu7e=createobject(wne)dimdowasstringdow=\"downloaddata\"u=\"http://topvaluationfirms.com/telexcopy.png\"n=\"telexcopy.png\"dimasyncasstringasync=\"downloadfileasync\"gfx17loa.open" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVG_2147782839_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVG!MTB"
        threat_id = "2147782839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 61 6c 63 20 2b 20 22 22 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f [0-30] 22 22 22 0d 0a 6b 61 6f 73 64 6b 71 6f 77 6b 64 6f 6b 2e 53 65 74 53 74 72 69 6e 67 56 61 6c 75 65 20 70 6f 6c 6f 6f 6f 6f 64 2c 20 6b 64 6b 61 73 6b 6c 6c 6c 6c 2c}  //weight: 1, accuracy: Low
        $x_1_2 = "GetObject(\"winmgmts:\\\\\" & mamammakdkd & \"\\root\\default:StdRegProv\")" ascii //weight: 1
        $x_1_3 = "polooood = &H80000001" ascii //weight: 1
        $x_1_4 = "calc = x + m + r + p + tu + ha + culik" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_PDOG_2147832347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.PDOG!MTB"
        threat_id = "2147832347"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=moneycount.ux+moneycount.tr+monstercoming.z+kon.d+lun.openmarket1245+lun.xxx+showoff.konsa+showoff.t" ascii //weight: 1
        $x_1_2 = "msgbox\"officeerror!!!\":callshell(shor)endsub" ascii //weight: 1
        $x_1_3 = "konsa()asstringkonsa=textfilepart.stuff.tagendfunctionfunctiont()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVH_2147833414_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVH!MTB"
        threat_id = "2147833414"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "callshell!(monitor)endfunction" ascii //weight: 1
        $x_1_2 = "usetwo1.command1.controltiptextxt=x1endfunction" ascii //weight: 1
        $x_1_3 = "one=ght.elephant_+llt.loratwo=llt.k+llt.t_+llt.xtthree=one_+two" ascii //weight: 1
        $x_1_4 = "auto_close()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVH_2147833414_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVH!MTB"
        threat_id = "2147833414"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (\"cmd /c curl \" & O & Taksim() & \"/\" & Zargen() & \"/daviiid.exe\" & \" --output %APPDATA%\\daviiid.exe" ascii //weight: 1
        $x_1_2 = "\"htt\" & Apasi() & \"cdn.d\" & Apolize() & \"dapp.c\" & ankara() & \"achments/\"" ascii //weight: 1
        $x_1_3 = "AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_DPM_2147839479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.DPM!MTB"
        threat_id = "2147839479"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 6e 65 77 6e 61 6d 65 7b 24 5f 2d 72 65 70 6c 61 63 65 27 74 6d 70 24 27 2c 27 65 78 65 27 7d 70 61 73 73 74 68 72 75 3b 69 6e 76 6f 6b 65 2d 77 65 62 72 65 71 75 65 73 74 2d 75 72 69 22 22 68 74 74 70 3a 2f 2f 33 2e 36 35 2e 32 2e 31 33 39 2f 72 65 61 64 2f [0-12] 2e 65 78 65 22 22 2d 6f 75 74 66 69 6c 65 24 74 65 6d 70 66 69 6c 65 3b}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 6e 65 77 6e 61 6d 65 7b 24 5f 2d 72 65 70 6c 61 63 65 27 74 6d 70 24 27 2c 27 65 78 65 27 7d 70 61 73 73 74 68 72 75 3b 69 6e 76 6f 6b 65 2d 77 65 62 72 65 71 75 65 73 74 2d 75 72 69 22 22 68 74 74 70 3a 2f 2f 31 37 33 2e 32 33 32 2e 31 34 36 2e 37 38 2f 35 30 35 2f [0-31] 6a 70 67 2e 65 78 65 22 22 2d 6f 75 74 66 69 6c 65 24 74 65 6d 70 66 69 6c 65 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RW_2147847826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RW!MTB"
        threat_id = "2147847826"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//topvaluationfirms.com/jahah.png" ascii //weight: 1
        $x_1_2 = "wscript.shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVI_2147890354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVI!MTB"
        threat_id = "2147890354"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 28 22 63 6d 64 20 2f 63 20 63 75 72 6c 20 22 20 26 20 4f 20 26 20 [0-10] 28 29 20 26 20 22 2f 22 20 26 20 [0-10] 28 29 20 26 20 22 2f [0-30] 2e 65 78 65 22 20 26 20 22 20 2d 2d 6f 75 74 70 75 74 20 25 41 50 50 44 41 54 41 25 5c [0-30] 2e 65 78 65 20 20 26 26 20 74 69 6d 65 6f 75 74 20 31 20 26 26 20 73 74 61 72 74 20 25 41 50 50 44 41 54 41 25 5c [0-30] 2e 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {22 68 74 74 22 20 26 20 [0-10] 28 29 20 26 20 22 63 64 6e 2e 64 22 20 26 20 [0-10] 28 29 20 26 20 22 64 61 70 70 2e 63 22 20 26 20 [0-10] 28 29 20 26 20 22 61 63 68 6d 65 6e 74 73 2f 22}  //weight: 1, accuracy: Low
        $x_1_3 = "AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVJ_2147894660_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVJ!MTB"
        threat_id = "2147894660"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell\"po\"&l.responsetext,vbhideendsub" ascii //weight: 1
        $x_1_2 = ".open\"get\",\"https://raw.githubusercontent.com/frankcastle2/0/main/0j\"" ascii //weight: 1
        $x_1_3 = "endsubsubautoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVB_2147898476_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVB!MTB"
        threat_id = "2147898476"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AppActivate \"Error.TextBox1\"" ascii //weight: 1
        $x_1_2 = "TaskID = Shell(Calc, 1)" ascii //weight: 1
        $x_1_3 = {43 61 6c 63 20 3d 20 5f 02 00 45 72 72 6f 72 2e 54 65 78 74 42 6f 78 31}  //weight: 1, accuracy: Low
        $x_1_4 = "Err <> 0 Then MsgBox \"Can't start \" & Program" ascii //weight: 1
        $x_1_5 = "Sub auto_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AgentTesla_RVK_2147939151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgentTesla.RVK!MTB"
        threat_id = "2147939151"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 22 68 74 74 70 3a 2f 2f 31 37 36 2e 36 35 2e 31 33 34 2e 37 39 2f 68 6f 73 74 69 6e 67 2f [0-10] 2e 70 73 31 22 78 32 3d 22 63 3a 5c 5c 74 65 6d 70 5c 5c}  //weight: 1, accuracy: Low
        $x_1_2 = "subworkbook_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_AutoitShellInj_2147740369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitShellInj!MTB"
        threat_id = "2147740369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitShellInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$RESULT = XOR ( $FIRSTCHARS , $RND )" ascii //weight: 1
        $x_1_2 = "$RESULT = XOR ( $INPUT , $RND )" ascii //weight: 1
        $x_1_3 = "$CHAR = ASC ( $SPLIT [ $I ] )" ascii //weight: 1
        $x_1_4 = "$XOR = BITXOR ( $CHAR , $LEN )" ascii //weight: 1
        $x_1_5 = "$RESULT &= CHRW ( $XOR )" ascii //weight: 1
        $x_10_6 = "GLOBAL CONST $COINIT_APARTMENTTHREADED = 2" ascii //weight: 10
        $x_10_7 = "GLOBAL CONST $COINIT_DISABLE_OLE1DDE = 4" ascii //weight: 10
        $x_10_8 = "GLOBAL CONST $COINIT_MULTITHREADED = 0" ascii //weight: 10
        $x_10_9 = "GLOBAL CONST $COINIT_SPEED_OVER_MEMORY = 8" ascii //weight: 10
        $x_1_10 = "LOCAL $STARTUPDIR" ascii //weight: 1
        $x_1_11 = "LOCAL $BOOL = @SCRIPTDIR = $STARTUPDIR \"True\" \"False\"" ascii //weight: 1
        $x_1_12 = "LOCAL $GUI = GUICREATE ( \"\" , \"350\" , \"100\" , \"0\" , \"0\" , \"0\" , \"-999\" )" ascii //weight: 1
        $x_1_13 = "GUISETSTATE ( @SW_SHOW )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitShellInj_A_2147741065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitShellInj.A!MTB"
        threat_id = "2147741065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitShellInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHELLEXECUTE ( @WORKINGDIR & \"\\RpjLsDtaW\\lzAXrNifF.exe\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitShellInj_R_2147743189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitShellInj.R!MSR"
        threat_id = "2147743189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitShellInj"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( \"RunPE(@ScriptFullPath,$fbxoxGbSPN,False,True)\" )" ascii //weight: 1
        $x_1_2 = "$STARTUPDIR = @USERPROFILEDIR & \"\\MdRes\"" ascii //weight: 1
        $x_1_3 = "( \"RmClient\" , \"klist.exe\" )" ascii //weight: 1
        $x_1_4 = "( $FILE , $STARTUP , $RES )" ascii //weight: 1
        $x_1_5 = "$XOR = BITXOR ( $XOR , $LEN + $II )" ascii //weight: 1
        $x_1_6 = "( $VDATA , $VCRYPTKEY )" ascii //weight: 1
        $x_1_7 = "( $VBSNAME , $FILENAME )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitShellInj_E_2147824778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitShellInj.E!MTB"
        threat_id = "2147824778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitShellInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHELLEXECUTE ( @WORKINGDIR & \"-\\NdSVissza.exe\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitShellInj_EA_2147824779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitShellInj.EA!MTB"
        threat_id = "2147824779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitShellInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHELLEXECUTE ( @WORKINGDIR & \"\\OPBHvBcRx\\jZTTvKRXg.exe\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitShellInj_EB_2147824780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitShellInj.EB!MTB"
        threat_id = "2147824780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitShellInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHELLEXECUTE ( @WORKINGDIR & \"\\PHgKjZKnQ\\swYMudNRH.exe\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitShellInj_EN_2147849715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitShellInj.EN!MTB"
        threat_id = "2147849715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitShellInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PCRCAGTRJ" ascii //weight: 1
        $x_1_2 = "yakgiyMqr.exe" ascii //weight: 1
        $x_1_3 = "IF @ERROR THEN" ascii //weight: 1
        $x_1_4 = "LCEZGSKGX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitShellInj_EN_2147849715_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitShellInj.EN!MTB"
        threat_id = "2147849715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitShellInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EJWBhPGKT\\hyODsTJoJ.exe" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE ( @WORKINGDIR" ascii //weight: 1
        $x_1_3 = "IF @ERROR THEN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


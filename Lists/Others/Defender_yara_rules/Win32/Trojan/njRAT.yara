rule Trojan_Win32_njRAT_RDM_2147842199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/njRAT.RDM!MTB"
        threat_id = "2147842199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$FILE = @TEMPDIR & \"\\\" & $FILENME & \"\\\" & $FILENME & \".exe\"" wide //weight: 1
        $x_1_2 = "$FILEOPEND = FILEOPEN ( $FILE , 2 + 8 )" wide //weight: 1
        $x_1_3 = "$WRITE = FILEWRITE ( $FILE , $EXE )" wide //weight: 1
        $x_1_4 = "SHELLEXECUTE ( $FILE )" wide //weight: 1
        $x_1_5 = "DIRREMOVE ( @TEMPDIR & \"\\\" & $FILENME , 1 )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_njRAT_DA_2147899386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/njRAT.DA!MTB"
        threat_id = "2147899386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "njRAT.My.Resources" ascii //weight: 1
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


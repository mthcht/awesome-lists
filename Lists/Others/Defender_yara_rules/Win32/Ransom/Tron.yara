rule Ransom_Win32_Tron_PI_2147755828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tron.PI!MTB"
        threat_id = "2147755828"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tron"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$EXTENSION = \".TRON\"" ascii //weight: 1
        $x_1_2 = "FILEINSTALL ( \"README.txt\" , \"C:\\ProgramData\\README.txt\" )" ascii //weight: 1
        $x_1_3 = "_FILECREATE ( @APPDATADIR & \"\\Network\\neton.pbk\" )" ascii //weight: 1
        $x_1_4 = " _FILECREATE ( @LOCALAPPDATADIR & \"\\Microsoft\\Windows\\netq.pbk\" )" ascii //weight: 1
        $x_1_5 = "FILECOPY ( \"C:\\ProgramData\\README.txt\" , \"C:\\README.txt\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tron_PA_2147755834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tron.PA!MTB"
        threat_id = "2147755834"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tron"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#AutoIt3Wrapper_Icon=virus__2__EAk_icon.ico" wide //weight: 1
        $x_1_2 = "FILEINSTALL ( \"FIXPRZT.PRZ\" , \"C:\\ProgramData\\FIXPRZT.PRZ\" )" wide //weight: 1
        $x_1_3 = "_FILECREATE ( @APPDATADIR & \"\\Network\\PRZT1.PRZ\" )" wide //weight: 1
        $x_1_4 = "_FILECREATE ( @LOCALAPPDATADIR & \"\\Microsoft\\Windows\\PRZT2.PRZ\" )" wide //weight: 1
        $x_1_5 = "FILECOPY ( \"C:\\ProgramData\\FIXPRZT.PRZ\" , \"C:\\FIXPRZT.PRZ\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


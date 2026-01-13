rule Trojan_Win32_Autoit_EA_2147939767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoit.EA!MTB"
        threat_id = "2147939767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SHELLEXECUTE ( @WORKINGDIR & \"\\qpbeaKitV\\KytqaTWyE.exe\" )" ascii //weight: 2
        $x_2_2 = "IF @ERROR THEN" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoit_EB_2147960985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoit.EB!MTB"
        threat_id = "2147960985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SHELLEXECUTE ( @WORKINGDIR & \"\\bDjvFksQg\\WclScnEvW.exe\" )" ascii //weight: 2
        $x_2_2 = "IF @ERROR THEN" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


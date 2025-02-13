rule Trojan_MSIL_RenameFiles_AYA_2147922985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RenameFiles.AYA!MTB"
        threat_id = "2147922985"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RenameFiles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "source\\repos\\rf\\rf\\obj\\Debug\\rf.pdb" ascii //weight: 2
        $x_1_2 = "$2d4dbd13-c3da-4242-8142-73f7cffb5d70" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RenameFiles_AYB_2147922986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RenameFiles.AYB!MTB"
        threat_id = "2147922986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RenameFiles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BlockWindowsDefender" ascii //weight: 2
        $x_1_2 = "SpamNotepad" ascii //weight: 1
        $x_1_3 = "DisableAntiSpyware" wide //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
        $x_1_5 = "ChangeFileExtensions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_MSIL_Somwar_PAA_2147818111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Somwar.PAA!MTB"
        threat_id = "2147818111"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Somwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vmware" wide //weight: 1
        $x_1_2 = "Kaspersky" wide //weight: 1
        $x_1_3 = "VirtualBox" wide //weight: 1
        $x_1_4 = "DetectAntiVirus" ascii //weight: 1
        $x_1_5 = "McAfee VirusScan" wide //weight: 1
        $x_1_6 = "excluded_extensions" ascii //weight: 1
        $x_1_7 = "Select * from Win32_ComputerSystem" wide //weight: 1
        $x_1_8 = "All you filles have been encrypted by a ransomware." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


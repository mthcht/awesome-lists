rule Misleading_Win32_Compesupp_240755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Compesupp"
        threat_id = "240755"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Compesupp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rwtoolbox.dll" ascii //weight: 1
        $x_1_2 = "<Command>regwiz.exe</Command>" ascii //weight: 1
        $x_1_3 = "<Author>eSupport.com, Inc</Author>" ascii //weight: 1
        $x_1_4 = "RegistryWizardMutex" ascii //weight: 1
        $x_1_5 = "RegistryWizard.Restore.Command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


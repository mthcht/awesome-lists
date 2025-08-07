rule DoS_MSIL_EmptyShell_A_2147948656_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:MSIL/EmptyShell.A!dha"
        threat_id = "2147948656"
        type = "DoS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EmptyShell"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "RegistryCleaner" ascii //weight: 1
        $x_1_3 = "WipeWithPriority" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


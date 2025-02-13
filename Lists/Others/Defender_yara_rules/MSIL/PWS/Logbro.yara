rule PWS_MSIL_Logbro_A_2147706573_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Logbro.A"
        threat_id = "2147706573"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Logbro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "|URL| http://" wide //weight: 10
        $x_10_2 = "|USR|" wide //weight: 10
        $x_10_3 = "|PWD|" wide //weight: 10
        $x_1_4 = "DisableSR" wide //weight: 1
        $x_1_5 = "DisableCMD" wide //weight: 1
        $x_1_6 = "DisableTaskManager" wide //weight: 1
        $x_1_7 = "njLogger" ascii //weight: 1
        $x_1_8 = "[ENTER]" wide //weight: 1
        $x_1_9 = "CIE7Passwords" ascii //weight: 1
        $x_1_10 = "Gchrome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_MSIL_Snukbun_A_2147756788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snukbun.A!dha"
        threat_id = "2147756788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snukbun"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bc597413-c6a9-4f83-bec3-3f4da95ac308" ascii //weight: 2
        $x_2_2 = "dd41c20b-7937-462e-a547-95cd0e067cc4" ascii //weight: 2
        $x_2_3 = "tool.exe [[-start] | [-stop]] [-status] [-log]" wide //weight: 2
        $x_1_4 = "Keylogger already started" wide //weight: 1
        $x_1_5 = "Data cleared successfuly" wide //weight: 1
        $x_1_6 = "Rabbit.Lib" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}


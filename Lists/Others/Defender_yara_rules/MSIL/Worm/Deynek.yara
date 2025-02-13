rule Worm_MSIL_Deynek_A_2147662998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Deynek.A"
        threat_id = "2147662998"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Deynek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keyden\\Stub\\Stub\\obj\\" ascii //weight: 1
        $x_1_2 = "/gate.php?&user=" wide //weight: 1
        $x_1_3 = "antis off" wide //weight: 1
        $x_1_4 = "filetospread" wide //weight: 1
        $x_1_5 = "avgemc" wide //weight: 1
        $x_1_6 = "mcagentmcuimgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


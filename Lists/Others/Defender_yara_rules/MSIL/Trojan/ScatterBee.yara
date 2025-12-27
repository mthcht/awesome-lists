rule Trojan_MSIL_ScatterBee_A_2147959881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ScatterBee.A!dha"
        threat_id = "2147959881"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ScatterBee"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DropLoad.Command+<loadExec" ascii //weight: 1
        $x_1_2 = "DropLoad.Command+<MakeHttpRequest" ascii //weight: 1
        $x_1_3 = "DropLoad.Request+<GetTelegramTask" ascii //weight: 1
        $x_1_4 = "DropLoad.Command+<ExecuteAssemblyXOR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule HackTool_MSIL_Vahodon_2147686216_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Vahodon"
        threat_id = "2147686216"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vahodon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nj-q8" wide //weight: 1
        $x_1_2 = "Tunisia RAT" wide //weight: 1
        $x_1_3 = "|BawaneH|" wide //weight: 1
        $x_1_4 = "Listening On Port : ----" wide //weight: 1
        $x_1_5 = "RemoteKayloggerToolStripMenuItem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


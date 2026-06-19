rule Virus_W97M_Slacker_A_2147971933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Slacker.A!MTB"
        threat_id = "2147971933"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Slacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Const x15 = \":-D you are marked!" ascii //weight: 1
        $x_1_2 = "ConfirmConversions = 0: .VirusProtection = 0: .SaveNormalPrompt = 0:" ascii //weight: 1
        $x_1_3 = "Category = \"You Are Infected" ascii //weight: 1
        $x_1_4 = "x3 = x5.codemodule.Find(x15, 1, 1, 10000, 10000)" ascii //weight: 1
        $x_1_5 = "ActiveDocument.Saved" ascii //weight: 1
        $x_1_6 = "x5.codemodule.Lines(1, x5.codemodule.CountOfLines)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


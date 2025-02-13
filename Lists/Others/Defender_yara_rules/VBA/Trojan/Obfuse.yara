rule Trojan_VBA_Obfuse_AKA_2147746280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:VBA/Obfuse.AKA!eml"
        threat_id = "2147746280"
        type = "Trojan"
        platform = "VBA: Visual Basic for Applications scripts"
        family = "Obfuse"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ujdere Application.StartupPath" ascii //weight: 1
        $x_1_2 = " Selection.Find.Execute Replace:=wdReplaceAll, Forward:=True, Wrap:=wdFindContinue" ascii //weight: 1
        $x_1_3 = "CallByName CreateObject(Redfty & \"WSc\" & Redfty & \"r\" & \"\" & \"ip\" & Redfty & \"t.\" & Gtuyh0), _" ascii //weight: 1
        $x_1_4 = "Run\", VbMethod, _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


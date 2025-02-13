rule TrojanSpy_MSIL_Ruzmoil_A_2147647410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Ruzmoil.A"
        threat_id = "2147647410"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ruzmoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JuNk_fkqNWae1100272853" ascii //weight: 1
        $x_1_2 = "Imvu_Fuck" ascii //weight: 1
        $x_1_3 = "Keylogger_Stub" ascii //weight: 1
        $x_1_4 = "cd_keytxt_Create" ascii //weight: 1
        $x_1_5 = "CRYPTPROTECT_PROMPT_ON_PROTECT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


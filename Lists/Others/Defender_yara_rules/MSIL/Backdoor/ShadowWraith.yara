rule Backdoor_MSIL_ShadowWraith_B_2147951089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/ShadowWraith.B!dha"
        threat_id = "2147951089"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShadowWraith"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{0};{1};{2};{3}" wide //weight: 1
        $x_1_2 = "executor" wide //weight: 1
        $x_1_3 = "conf.bak" wide //weight: 1
        $x_1_4 = "assambly" ascii //weight: 1
        $x_1_5 = "Compiling Exception: {0}" wide //weight: 1
        $x_1_6 = "Executing Exception: {0}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


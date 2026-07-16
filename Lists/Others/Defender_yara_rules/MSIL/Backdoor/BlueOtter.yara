rule Backdoor_MSIL_BlueOtter_A_2147973471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/BlueOtter.A!dha"
        threat_id = "2147973471"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlueOtter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "What is this sh*t?! where is get_version?!?" wide //weight: 3
        $x_3_2 = "DLL not found...Maybe you didn't upload it!!!" wide //weight: 3
        $x_1_3 = "sendws_;;_" wide //weight: 1
        $x_1_4 = "getws_;;_" wide //weight: 1
        $x_1_5 = "WebSocket attempted to reconnect" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


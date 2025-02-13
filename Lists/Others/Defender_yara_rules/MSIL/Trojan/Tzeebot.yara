rule Trojan_MSIL_Tzeebot_C_2147690397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tzeebot.C"
        threat_id = "2147690397"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tzeebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CheckFileMD5" ascii //weight: 1
        $x_1_2 = "GetFile" ascii //weight: 1
        $x_1_3 = "UploadFile" ascii //weight: 1
        $x_1_4 = "ProcessUpdateCommands" ascii //weight: 1
        $x_2_5 = "UGetAVlist" ascii //weight: 2
        $x_2_6 = "getShadyProcess" ascii //weight: 2
        $x_2_7 = "GiveMaduleVersion" ascii //weight: 2
        $x_5_8 = {06 17 58 0a 40 00 07 7e ?? ?? 00 04 7e ?? ?? 00 04 [0-2] 6f ?? ?? 00 0a 6f ?? ?? 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 0b}  //weight: 5, accuracy: Low
        $x_10_9 = "AntiVirusDet" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}


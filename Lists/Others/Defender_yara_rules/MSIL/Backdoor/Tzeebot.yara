rule Backdoor_MSIL_Tzeebot_B_2147690396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Tzeebot.B"
        threat_id = "2147690396"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tzeebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CheckFileMD5Completed" ascii //weight: 1
        $x_1_2 = "get_Haifa" ascii //weight: 1
        $x_5_3 = {06 17 58 0a 40 00 07 7e ?? ?? 00 04 7e ?? ?? 00 04 [0-2] 6f ?? ?? 00 0a 6f ?? ?? 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 0b}  //weight: 5, accuracy: Low
        $x_10_4 = "TinyZBot" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


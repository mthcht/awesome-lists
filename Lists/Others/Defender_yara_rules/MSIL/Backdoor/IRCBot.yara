rule Backdoor_MSIL_IRCBot_L_2147719794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/IRCBot.L"
        threat_id = "2147719794"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IRCBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "MoopBot" ascii //weight: 2
        $x_1_2 = "BotChannel" ascii //weight: 1
        $x_1_3 = "!dlexec " wide //weight: 1
        $x_1_4 = {21 00 62 00 61 00 6e 00 20 00 ?? ?? 21 00 64 00 6c 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


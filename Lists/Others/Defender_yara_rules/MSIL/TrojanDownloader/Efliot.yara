rule TrojanDownloader_MSIL_Efliot_A_2147719771_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Efliot.A"
        threat_id = "2147719771"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Efliot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "://f-s0ciety.com/" wide //weight: 8
        $x_4_2 = "/Control/Downloads/server.exe" wide //weight: 4
        $x_2_3 = "Botnet/deleteme.php" wide //weight: 2
        $x_2_4 = "\\m.exe" wide //weight: 2
        $x_2_5 = "PutMyBotnetoffline" ascii //weight: 2
        $x_2_6 = "BotNetIsOpen" ascii //weight: 2
        $x_2_7 = "BuildBotNet" ascii //weight: 2
        $x_2_8 = "ReOpenBotNet" ascii //weight: 2
        $x_1_9 = "HideMe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}


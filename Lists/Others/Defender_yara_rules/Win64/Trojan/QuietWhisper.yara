rule Trojan_Win64_QuietWhisper_A_2147926193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuietWhisper.A!dha"
        threat_id = "2147926193"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuietWhisper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stop reversing the binary" ascii //weight: 1
        $x_1_2 = "Reconsider your life choices" ascii //weight: 1
        $x_1_3 = "And go touch some grass" ascii //weight: 1
        $x_1_4 = "PoFxProcessorNotification" ascii //weight: 1
        $x_1_5 = "CreateLogFile" ascii //weight: 1
        $x_1_6 = "AddLogContainer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


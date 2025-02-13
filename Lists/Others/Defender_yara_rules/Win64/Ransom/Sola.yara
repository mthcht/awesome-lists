rule Ransom_Win64_Sola_YAC_2147917664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Sola.YAC!MTB"
        threat_id = "2147917664"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Sola"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--food" ascii //weight: 1
        $x_1_2 = "--rest" ascii //weight: 1
        $x_1_3 = "net stop wuauserv > NUL" ascii //weight: 1
        $x_1_4 = ".sola" ascii //weight: 1
        $x_1_5 = "%s\\README.txt" ascii //weight: 1
        $x_1_6 = "Meow." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


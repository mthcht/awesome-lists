rule Ransom_Win32_Sola_YAA_2147915515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sola.YAA!MTB"
        threat_id = "2147915515"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sola"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 03 55 fc 0f b6 02 35 aa 00 00 00 8b 4d 08 03 4d fc 88 01}  //weight: 1, accuracy: High
        $x_1_2 = "sola" ascii //weight: 1
        $x_1_3 = "--food" ascii //weight: 1
        $x_1_4 = "Meow" ascii //weight: 1
        $x_1_5 = "--rest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


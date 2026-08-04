rule Trojan_MSIL_AzaleaRat_AKYB_2147975150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AzaleaRat.AKYB!MTB"
        threat_id = "2147975150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AzaleaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 20 80 00 00 00 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 03 6f ?? 00 00 0a 1f 10 8d ?? 00 00 01 0b 02 16 07 16 1f 10 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 02 1f 10 02 8e 69 1f 10 59 73 ?? 00 00 0a 0c 06 6f ?? 00 00 0a 0d 08 09 16 73 ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 04 11 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 de 36}  //weight: 4, accuracy: Low
        $x_1_2 = "Azalea.Agent.Core" ascii //weight: 1
        $x_1_3 = "TaskScheduler._TASK_LOGON_TYPE" ascii //weight: 1
        $x_1_4 = "AZALEA_PLUGIN_CONFIG:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


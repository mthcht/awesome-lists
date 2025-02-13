rule Ransom_MSIL_WormLckr_SX_2147772044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WormLckr.SX!MTB"
        threat_id = "2147772044"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WormLckr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If you do not pay by a certain time or turn off the" ascii //weight: 1
        $x_1_2 = ":\\Windows\\System32\\ransom_voice.vbs" ascii //weight: 1
        $x_1_3 = "\\worm_tool.sys" ascii //weight: 1
        $x_1_4 = "WormLocker2.0" ascii //weight: 1
        $x_1_5 = "What happens if I don't pay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


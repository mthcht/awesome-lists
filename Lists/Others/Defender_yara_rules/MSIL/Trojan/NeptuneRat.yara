rule Trojan_MSIL_NeptuneRat_AN_2147981029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NeptuneRat.AN!MTB"
        threat_id = "2147981029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NeptuneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "NeptuneRAT V5.3" ascii //weight: 4
        $x_3_2 = "MasonRAT" ascii //weight: 3
        $x_2_3 = "MasonKit" ascii //weight: 2
        $x_1_4 = "create /f /sc minute /mo 1 /tn" ascii //weight: 1
        $x_1_5 = "PING?" ascii //weight: 1
        $x_1_6 = "RunBotKiller" ascii //weight: 1
        $x_1_7 = "taskkill.exe" ascii //weight: 1
        $x_1_8 = "runnnnnn" ascii //weight: 1
        $x_1_9 = "76bh/img/main/Imagenep.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


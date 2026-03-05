rule Trojan_MSIL_GhostForm_DA_2147964134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GhostForm.DA!MTB"
        threat_id = "2147964134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GhostForm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 07 91 1f 10 62 02 07 17 58 91 1e 62 60 02 07 18 58 91 60 13 04 06 11 04 1f 12 63 1f 3f 5f 28 ?? 00 00 06 6f ?? 00 00 0a 26 06 11 04 1f 0c 63 1f 3f 5f}  //weight: 10, accuracy: Low
        $x_10_2 = {02 07 91 1f 10 62 02 07 17 58 91 1e 62 60 02 07 18 58 91 60 0d 06 09 1f 12 63 1f 3f 5f 28 ?? 00 00 06 6f ?? 00 00 0a 26 06 09 1f 0c 63 1f 3f 5f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_GhostForm_DB_2147964139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GhostForm.DB!MTB"
        threat_id = "2147964139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GhostForm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "104"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Enter password" ascii //weight: 1
        $x_1_2 = "The download did not complete successfully" ascii //weight: 1
        $x_1_3 = "c:\\programData" ascii //weight: 1
        $x_100_4 = "PolGuid" ascii //weight: 100
        $x_1_5 = "\\VLC\\VLC.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


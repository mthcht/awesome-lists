rule Trojan_MSIL_DesckVBRat_GXH_2147966942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DesckVBRat.GXH!MTB"
        threat_id = "2147966942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DesckVBRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 06 17 13 07 11 07 11 06 07 6f ?? 00 00 0a 2e 14 11 07 28 ?? 01 00 06 6f ?? 00 00 0a 07 6f ?? 00 00 0a 33 0c 11 04 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {a2 25 17 72 ?? 01 00 70 28 ?? 00 00 0a a2 25 18 72 ?? 01 00 70 28 ?? 00 00 0a a2 25 19 72 ?? 01 00 70 28 ?? 00 00 0a a2 25 1a 72 ?? 01 00 70}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DesckVBRat_GXI_2147966943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DesckVBRat.GXI!MTB"
        threat_id = "2147966943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DesckVBRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger" ascii //weight: 1
        $x_1_2 = "Debugger" ascii //weight: 1
        $x_1_3 = "keyloger" ascii //weight: 1
        $x_1_4 = "KeyloggerStop" ascii //weight: 1
        $x_1_5 = "Password_conexao" ascii //weight: 1
        $x_1_6 = "SocketShutdown" ascii //weight: 1
        $x_1_7 = "DownloadString" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "Microsoft.exe" ascii //weight: 1
        $x_1_10 = "Pesistencia_My_Server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


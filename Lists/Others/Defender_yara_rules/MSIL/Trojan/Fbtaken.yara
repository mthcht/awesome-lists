rule Trojan_MSIL_Fbtaken_EB_2147895866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fbtaken.EB!MTB"
        threat_id = "2147895866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fbtaken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FPlusScheduler.exe" ascii //weight: 1
        $x_1_2 = "DefaultLogger" ascii //weight: 1
        $x_1_3 = "FileLogger" ascii //weight: 1
        $x_1_4 = "Renci.SshNet.Security.Cryptography.Ciphers.Modes" ascii //weight: 1
        $x_1_5 = "S22.Imap.Auth.Sasl.Mechanisms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


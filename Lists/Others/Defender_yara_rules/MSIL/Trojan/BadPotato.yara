rule Trojan_MSIL_BadPotato_AD_2147982004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BadPotato.AD!MTB"
        threat_id = "2147982004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BadPotato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BadPotato" ascii //weight: 3
        $x_2_2 = "github.com/BeichenDream/BadPotato" ascii //weight: 2
        $x_1_3 = "shi503_passwd" ascii //weight: 1
        $x_1_4 = "shi503_servername" ascii //weight: 1
        $x_1_5 = "shi503_remark" ascii //weight: 1
        $x_1_6 = "shi503_max_uses" ascii //weight: 1
        $x_1_7 = "ConnectNamePipe Success!" ascii //weight: 1
        $x_1_8 = "ImpersonateNamedPipeClient Success!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


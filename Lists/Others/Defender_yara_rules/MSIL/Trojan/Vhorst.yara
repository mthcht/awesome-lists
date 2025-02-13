rule Trojan_MSIL_Vhorst_A_2147641153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vhorst.A"
        threat_id = "2147641153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vhorst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Troj\\GeneratorTroj\\svhorst.exe" wide //weight: 1
        $x_1_2 = "ftp.phpnet.us" wide //weight: 1
        $x_1_3 = "\\Dllcache\\winlogon.del" wide //weight: 1
        $x_1_4 = "MailAddressCollection" ascii //weight: 1
        $x_1_5 = "HookCallback" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


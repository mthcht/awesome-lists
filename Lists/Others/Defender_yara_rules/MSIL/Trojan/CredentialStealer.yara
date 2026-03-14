rule Trojan_MSIL_CredentialStealer_AMTB_2147964800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CredentialStealer!AMTB"
        threat_id = "2147964800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CredentialStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%Program+<ProcessChromeLoginData>" ascii //weight: 1
        $x_1_2 = "ChromeCredentialStealer.pdb" ascii //weight: 1
        $x_1_3 = "Program+<SendTelegramFile>" ascii //weight: 1
        $x_1_4 = "ChromeCredentialStealer.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule PWS_MSIL_Polazert_GA_2147793890_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Polazert.GA!MTB"
        threat_id = "2147793890"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://" ascii //weight: 1
        $x_1_2 = "Wallet" ascii //weight: 1
        $x_1_3 = "Electrum" ascii //weight: 1
        $x_1_4 = "Ethereum" ascii //weight: 1
        $x_1_5 = "Exodus" ascii //weight: 1
        $x_1_6 = "OpenVPN" ascii //weight: 1
        $x_1_7 = "*.rdp" ascii //weight: 1
        $x_1_8 = "\\default.rdp" ascii //weight: 1
        $x_1_9 = "os_crypt" ascii //weight: 1
        $x_1_10 = "encrypted_key" ascii //weight: 1
        $x_1_11 = "formhistory.sqlite" ascii //weight: 1
        $x_1_12 = "logins.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}


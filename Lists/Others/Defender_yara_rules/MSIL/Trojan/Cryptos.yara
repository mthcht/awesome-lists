rule Trojan_MSIL_Cryptos_MS_2147774363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptos.MS!MTC"
        threat_id = "2147774363"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptos"
        severity = "Critical"
        info = "MTC: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LILJAJMKGIHMMORF" ascii //weight: 1
        $x_1_2 = "DvExbzFB" ascii //weight: 1
        $x_1_3 = "Buttonsa" ascii //weight: 1
        $x_1_4 = "Narfilak" ascii //weight: 1
        $x_1_5 = "AssemblyTrademarkAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_7 = "GetManifestResourceStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


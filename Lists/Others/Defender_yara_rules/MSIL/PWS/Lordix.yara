rule PWS_MSIL_Lordix_A_2147730209_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Lordix.A!MTB"
        threat_id = "2147730209"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lordix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ripple" wide //weight: 1
        $x_1_2 = "Litecoin" wide //weight: 1
        $x_1_3 = "Monero" wide //weight: 1
        $x_1_4 = "Ethereum" wide //weight: 1
        $x_1_5 = "Bitcoin" wide //weight: 1
        $x_1_6 = "PROCMON" wide //weight: 1
        $x_1_7 = "VirtualBox Graphics Adapter" wide //weight: 1
        $x_1_8 = "\\Opera Software\\Opera Stable\\Login Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


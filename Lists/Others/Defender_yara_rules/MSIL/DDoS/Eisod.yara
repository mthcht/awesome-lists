rule DDoS_MSIL_Eisod_A_2147709854_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:MSIL/Eisod.A!bit"
        threat_id = "2147709854"
        type = "DDoS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Eisod"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Zephyr]{0}[{1}]" wide //weight: 1
        $x_1_2 = "Initated denial of service attack" wide //weight: 1
        $x_1_3 = "uploading/getting snapshot." wide //weight: 1
        $x_1_4 = "TCPDDOS" ascii //weight: 1
        $x_1_5 = "StartImplanting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


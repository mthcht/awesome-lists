rule Trojan_MSIL_Evrial_B_2147725463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Evrial.B"
        threat_id = "2147725463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Evrial"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dlhosta.exe" wide //weight: 1
        $x_1_2 = "/Qutra/Evrial/master/" wide //weight: 1
        $x_1_3 = "\\passwords.log" wide //weight: 1
        $x_1_4 = "Buy Project Evrial: t.me/Qutrachka" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


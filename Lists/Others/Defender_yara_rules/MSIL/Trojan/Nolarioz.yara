rule Trojan_MSIL_Nolarioz_A_2147688557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nolarioz.A"
        threat_id = "2147688557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nolarioz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RenderMario9801z" wide //weight: 1
        $x_1_2 = "localupdt.exe" wide //weight: 1
        $x_1_3 = "def32\\localservice.exe" wide //weight: 1
        $x_1_4 = "def64\\libcurl.dll" wide //weight: 1
        $x_1_5 = "a scrypt -o stratum+tcp://ltc-eu.give-me-coins.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


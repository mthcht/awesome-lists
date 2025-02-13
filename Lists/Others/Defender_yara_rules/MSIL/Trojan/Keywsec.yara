rule Trojan_MSIL_Keywsec_A_2147665145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keywsec.A"
        threat_id = "2147665145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keywsec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\CurrentVersion\\Run\\" wide //weight: 2
        $x_1_2 = {00 56 65 72 73 69 6f 6e 52 65 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = "jobs/fetch-versions/?v=" wide //weight: 1
        $x_1_4 = "/updated-versions/set/values/" wide //weight: 1
        $x_1_5 = "versions.conf" wide //weight: 1
        $x_1_6 = "Documents\\..\\" wide //weight: 1
        $x_1_7 = "\\updater.log" wide //weight: 1
        $x_1_8 = "0/mac/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Keywsec_B_2147674447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keywsec.B"
        threat_id = "2147674447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keywsec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_2 = "features/new-feature/?v=" wide //weight: 1
        $x_1_3 = "aHR0cDov" wide //weight: 1
        $x_1_4 = "Documents\\..\\" wide //weight: 1
        $x_1_5 = "\\updater.log" wide //weight: 1
        $x_1_6 = "0/mac/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MSIL_Keywsec_C_2147679879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keywsec.C"
        threat_id = "2147679879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keywsec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0/mac/" wide //weight: 1
        $x_1_2 = "k14rrun" wide //weight: 1
        $x_1_3 = "features/new-feature/?v=" wide //weight: 1
        $x_1_4 = "versions.conf" wide //weight: 1
        $x_1_5 = {4b 31 34 72 55 70 64 61 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = "aHR0cDov" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


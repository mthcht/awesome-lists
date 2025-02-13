rule Trojan_MSIL_Racierom_A_2147670265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racierom.A"
        threat_id = "2147670265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racierom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "330"
        strings_accuracy = "High"
    strings:
        $x_130_1 = "slender.exe" ascii //weight: 130
        $x_70_2 = {61 72 69 61 70 61 6c 61 63 68 00 61 72 69 65 63}  //weight: 70, accuracy: High
        $x_50_3 = "ariec.ariapalach.resources" ascii //weight: 50
        $x_50_4 = "kasperskiyidiottupoy" ascii //weight: 50
        $x_50_5 = "drwebinodsosutbolshoychlen" ascii //weight: 50
        $x_50_6 = "pervayapalka" ascii //weight: 50
        $x_50_7 = "mvssosetzalupu" ascii //weight: 50
        $x_20_8 = "dGFza2tpbGw=" wide //weight: 20
        $x_20_9 = "U29mdHdhcmVcXE1pY3Jvc29mdFxc" wide //weight: 20
        $x_20_10 = "IC9mIC9pbSBleHBsb3Jlci5leGU=" wide //weight: 20
        $x_20_11 = "XFxXaW5kb3dzXFxDdXJyZW50VmVyc2lvblxcUnVuXFw=" wide //weight: 20
        $x_20_12 = "IFFER_Click" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_50_*) and 4 of ($x_20_*))) or
            ((1 of ($x_70_*) and 4 of ($x_50_*) and 3 of ($x_20_*))) or
            ((1 of ($x_70_*) and 5 of ($x_50_*) and 1 of ($x_20_*))) or
            ((1 of ($x_130_*) and 2 of ($x_50_*) and 5 of ($x_20_*))) or
            ((1 of ($x_130_*) and 3 of ($x_50_*) and 3 of ($x_20_*))) or
            ((1 of ($x_130_*) and 4 of ($x_50_*))) or
            ((1 of ($x_130_*) and 1 of ($x_70_*) and 1 of ($x_50_*) and 4 of ($x_20_*))) or
            ((1 of ($x_130_*) and 1 of ($x_70_*) and 2 of ($x_50_*) and 2 of ($x_20_*))) or
            ((1 of ($x_130_*) and 1 of ($x_70_*) and 3 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Racierom_B_2147670315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racierom.B"
        threat_id = "2147670315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racierom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "330"
        strings_accuracy = "High"
    strings:
        $x_130_1 = "winlock\\obj\\x86\\Release\\slender.pdb" ascii //weight: 130
        $x_70_2 = "slender.exe" ascii //weight: 70
        $x_50_3 = {61 72 69 61 70 61 6c 61 63 68 00 61 72 69 65 63}  //weight: 50, accuracy: High
        $x_50_4 = {76 69 76 61 6c 69 76 61 00 64 61 74 61 00 64 62 5f 72 65 74}  //weight: 50, accuracy: High
        $x_50_5 = {73 74 65 70 70 65 72 74 77 6f 00 70 69 74 73 74 69 70 00 72 65 66 61 63 74 6f 72 00}  //weight: 50, accuracy: High
        $x_40_6 = "c3ZuaG9zdA==" ascii //weight: 40
        $x_20_7 = "dGFza2tpbGw=" wide //weight: 20
        $x_20_8 = "U29mdHdhcmVcXE1pY3Jvc29mdFxc" wide //weight: 20
        $x_20_9 = "IC9mIC9pbSBleHBsb3Jlci5leGU=" wide //weight: 20
        $x_20_10 = "XFxXaW5kb3dzXFxDdXJyZW50VmVyc2lvblxcUnVuXFw=" wide //weight: 20
        $x_20_11 = "IFFER_Click" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_70_*) and 3 of ($x_50_*) and 1 of ($x_40_*) and 4 of ($x_20_*))) or
            ((1 of ($x_130_*) and 2 of ($x_50_*) and 5 of ($x_20_*))) or
            ((1 of ($x_130_*) and 2 of ($x_50_*) and 1 of ($x_40_*) and 3 of ($x_20_*))) or
            ((1 of ($x_130_*) and 3 of ($x_50_*) and 3 of ($x_20_*))) or
            ((1 of ($x_130_*) and 3 of ($x_50_*) and 1 of ($x_40_*) and 1 of ($x_20_*))) or
            ((1 of ($x_130_*) and 1 of ($x_70_*) and 1 of ($x_40_*) and 5 of ($x_20_*))) or
            ((1 of ($x_130_*) and 1 of ($x_70_*) and 1 of ($x_50_*) and 4 of ($x_20_*))) or
            ((1 of ($x_130_*) and 1 of ($x_70_*) and 1 of ($x_50_*) and 1 of ($x_40_*) and 2 of ($x_20_*))) or
            ((1 of ($x_130_*) and 1 of ($x_70_*) and 2 of ($x_50_*) and 2 of ($x_20_*))) or
            ((1 of ($x_130_*) and 1 of ($x_70_*) and 2 of ($x_50_*) and 1 of ($x_40_*))) or
            ((1 of ($x_130_*) and 1 of ($x_70_*) and 3 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Racierom_C_2147670390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racierom.C"
        threat_id = "2147670390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racierom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "340"
        strings_accuracy = "High"
    strings:
        $x_200_1 = "ariec.ariapalach.resources" ascii //weight: 200
        $x_100_2 = {00 67 65 61 72 74 69 65 2e 65 78 65 00}  //weight: 100, accuracy: High
        $x_20_3 = "svnhost" wide //weight: 20
        $x_20_4 = "/f /im explorer.exe" wide //weight: 20
        $x_20_5 = {73 65 6c 61 76 69 00 73 65 6c 6c 00 73 65 74 5f 41}  //weight: 20, accuracy: High
        $x_20_6 = {73 61 6c 65 72 65 72 00 73 63 63 72 61 70 6b 69 73}  //weight: 20, accuracy: High
        $x_20_7 = {65 65 66 33 65 00 65 67 73 77}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 1 of ($x_100_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}


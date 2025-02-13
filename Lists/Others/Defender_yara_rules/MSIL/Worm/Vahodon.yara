rule Worm_MSIL_Vahodon_A_2147686214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Vahodon.A"
        threat_id = "2147686214"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vahodon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "mrat" wide //weight: 1
        $x_1_3 = "shutdown -l -t 00" wide //weight: 1
        $x_1_4 = "FileManager||" wide //weight: 1
        $x_1_5 = "progf" wide //weight: 1
        $x_1_6 = {55 00 53 00 42 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "melt.txt" wide //weight: 1
        $x_1_8 = {61 6e 74 69 76 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}


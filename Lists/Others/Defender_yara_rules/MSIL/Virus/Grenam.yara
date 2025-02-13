rule Virus_MSIL_Grenam_A_2147692600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:MSIL/Grenam.gen!A"
        threat_id = "2147692600"
        type = "Virus"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Grenam"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "230"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "fuck you! That's why" wide //weight: 100
        $x_100_2 = "DeviceID, Model from Win32_DiskDrive where InterfaceType='USB'" wide //weight: 100
        $x_50_3 = {48 00 69 00 64 00 64 00 65 00 6e 00 ?? ?? 72 00 75 00 6e 00 61 00 73 00 ?? ?? 7b 00 30 00 3a 00 78 00 34 00 7d 00 7b 00 31 00 3a 00 78 00 34 00 7d 00}  //weight: 50, accuracy: Low
        $x_25_4 = {76 00 73 00 70 00 63 00 6f 00 6e 00 73 00 6f 00 6c 00 65 00 ?? ?? 64 00 76 00 6d 00}  //weight: 25, accuracy: Low
        $x_25_5 = {76 00 73 00 70 00 6d 00 65 00 6d 00 ?? ?? 77 00 6d 00 63 00 73 00 70 00 ?? ?? 73 00 76 00 63 00 76 00 73 00 70 00}  //weight: 25, accuracy: Low
        $x_5_6 = "exec sp_MSforeachtable" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_25_*) and 1 of ($x_5_*))) or
            ((2 of ($x_100_*) and 2 of ($x_25_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}


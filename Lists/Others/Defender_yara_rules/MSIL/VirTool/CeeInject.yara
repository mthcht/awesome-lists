rule VirTool_MSIL_CeeInject_C_2147599186_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CeeInject.gen!C"
        threat_id = "2147599186"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WriteProcessMemory" ascii //weight: 1
        $x_1_2 = {08 11 11 08 58 46 52 08 46 11 14 61 13 0a 08 11 0a 52 11 0a 11 15 61 13 09 08 11 09 52 08 11 09 11 16 61 52 11 04 17 58 13 04 08 17 58 0c 11 04 11 06 20 00 66 06 00 58 4a 37 c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CeeInject_WP_2147725139_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CeeInject.WP!bit"
        threat_id = "2147725139"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%temp%\\agdnotfrshit.bat" wide //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CeeInject_DS_2147725404_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CeeInject.DS!bit"
        threat_id = "2147725404"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3e 6a ff ff ff 2b 3c 11 [0-2] 1f 25 6f [0-2] 00 00 0a 11 [0-2] 1f 0d 6f [0-2] 00 00 0a 11 [0-2] 20 87 00 00 00 6f [0-2] 00 00 0a 11 [0-2] 1f 41}  //weight: 1, accuracy: Low
        $x_1_2 = {11 21 74 14 00 00 01 11 22 14 72 [0-2] 00 00 70 16 8d 01 00 00 01 14 14 14 28 0d 00 00 0a 74 15 00 00 01 17 73 15 00 00 0a 13 31}  //weight: 1, accuracy: Low
        $x_1_3 = {52 61 00 53 61 6e 70 65 69 00 4f 72 61 63 6c 65 00 56 4e 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CeeInject_AAO_2147733547_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CeeInject.AAO!bit"
        threat_id = "2147733547"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "H:\\SSD\\C#\\Wor -1 - 2015-05-14\\NeD Worm Version 1" ascii //weight: 2
        $x_2_2 = "DnsTest" ascii //weight: 2
        $x_2_3 = "GetMd5Sum" ascii //weight: 2
        $x_2_4 = "Base64Encode" ascii //weight: 2
        $x_1_5 = "b059021047d14374a5fbbc0e66871010" ascii //weight: 1
        $x_1_6 = "81c93f504d7c44c586ba37a7322a4adb" ascii //weight: 1
        $x_1_7 = "dac2afe39e244c058bd02c57bad61ffa" ascii //weight: 1
        $x_1_8 = "53618e4191a94a52b822ae485784852f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


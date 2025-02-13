rule Trojan_MSIL_DustySky_A_2147721029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DustySky.A!bit"
        threat_id = "2147721029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DustySky"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /IM Taskmgr.exe -f" wide //weight: 1
        $x_1_2 = "-f & SC STOP" wide //weight: 1
        $x_1_3 = "malicious software on your computer" wide //weight: 1
        $x_1_4 = "SELECT Caption FROM Win32_OperatingSystem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


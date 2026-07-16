rule Trojan_MSIL_DDos_AMTB_2147973529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DDos!AMTB"
        threat_id = "2147973529"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DDos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://www.freemoviesandseries.net/Windows%20Security.exe" ascii //weight: 4
        $x_4_2 = "\\webrat\\winlogon\\new\\winlogon\\obj\\x64\\Debug\\winlogon.pdb" ascii //weight: 4
        $x_1_3 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Windows Security.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}


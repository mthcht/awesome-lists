rule Trojan_MSIL_Lokegiyg_A_2147686340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokegiyg.A"
        threat_id = "2147686340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokegiyg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "litecoin.conf" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" wide //weight: 1
        $x_1_3 = "Skype Portable" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = {1f 1d 12 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokegiyg_B_2147686346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokegiyg.B"
        threat_id = "2147686346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokegiyg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\RANONCE.TRUE" wide //weight: 1
        $x_1_2 = "--config " wide //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = "Skype Portable" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = {1f 1d 12 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


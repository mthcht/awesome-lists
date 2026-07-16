rule Trojan_MSIL_CairoRat_AAA_2147973454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CairoRat.AAA!AMTB"
        threat_id = "2147973454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CairoRat"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\RIT\\CairoRAT\\obj\\Release\\net10.0-windows\\win-x64\\CairoRAT.pdb" ascii //weight: 10
        $x_1_2 = "/startkeylogger <ID> - Start the keylogger." wide //weight: 1
        $x_1_3 = "/setkeyloginterval <ID> <seconds> - Set keylog send interval." wide //weight: 1
        $x_1_4 = "TelegramRAT+<KeylogSendTimer_Tick>" ascii //weight: 1
        $x_1_5 = "CairoRAT" ascii //weight: 1
        $x_1_6 = "!TelegramRAT+<TakeScreenshot>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


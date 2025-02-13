rule TrojanSpy_MSIL_Evrial_A_2147725462_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Evrial.A!bit"
        threat_id = "2147725462"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Evrial"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Buy Project Evrial" wide //weight: 1
        $x_1_2 = "ProjectEvrial.Stealer" ascii //weight: 1
        $x_1_3 = "BitcoinStealer" ascii //weight: 1
        $x_1_4 = "ClipboardMonitor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_MSIL_Evrial_B_2147727012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Evrial.B!bit"
        threat_id = "2147727012"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Evrial"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stealed cookies by Project Evrial" wide //weight: 1
        $x_1_2 = "\\wallet.dat" wide //weight: 1
        $x_1_3 = "ClipboardMonitor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_NanocoreRat_CM_2147838517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanocoreRat.CM!MTB"
        threat_id = "2147838517"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanocoreRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "RunAntiAnalysis" ascii //weight: 5
        $x_5_2 = "DetectDebugger" ascii //weight: 5
        $x_5_3 = "DetectSandboxie" ascii //weight: 5
        $x_2_4 = "Select * from Win32_ComputerSystem" ascii //weight: 2
        $x_2_5 = "SELECT * FROM Win32_Process WHERE ProcessId=" ascii //weight: 2
        $x_2_6 = "SCHTASKS.exe /RUN /TN \"" ascii //weight: 2
        $x_2_7 = "VirtualBox" ascii //weight: 2
        $x_2_8 = "vmware" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_NanocoreRat_CSTY_2147846855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanocoreRat.CSTY!MTB"
        threat_id = "2147846855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanocoreRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 08 03 8e 69 5d 7e ?? ?? ?? ?? 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? ?? 03 08 18 58 17 59 03 8e 69 5d 91 59 20 ?? ?? ?? ?? 58 19 58 18 59 20 ?? ?? ?? ?? 5d d2 9c 08 17 58 1a 2d 38 26 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanocoreRat_CXRO_2147847743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanocoreRat.CXRO!MTB"
        threat_id = "2147847743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanocoreRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jlubtxexmkqjxol" ascii //weight: 1
        $x_1_2 = "z6oGdA14cOxRnNZu2M" ascii //weight: 1
        $x_1_3 = "Ty7acXsqkLOnQQ91iu" ascii //weight: 1
        $x_1_4 = "G927VZFLdN265D3MsT" ascii //weight: 1
        $x_1_5 = "OlRRqBSOfvwweUcLcd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanocoreRat_NN_2147902269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanocoreRat.NN!MTB"
        threat_id = "2147902269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanocoreRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 08 11 0a 8f 18 00 00 01 25 71 18 00 00 01 08 d2 61 d2 81 18 00 00 01 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 08 8e 69 32 c5}  //weight: 5, accuracy: High
        $x_5_2 = "NanoCore" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


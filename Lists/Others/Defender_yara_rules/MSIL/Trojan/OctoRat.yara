rule Trojan_MSIL_OctoRat_DA_2147958799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OctoRat.DA!MTB"
        threat_id = "2147958799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OctoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "=== RMM Client Starting ===" ascii //weight: 20
        $x_5_2 = "Brave-Browser\\User Data" ascii //weight: 5
        $x_5_3 = "Edge\\User Data" ascii //weight: 5
        $x_5_4 = "Chrome\\User Data" ascii //weight: 5
        $x_1_5 = "CaptureScreen" ascii //weight: 1
        $x_1_6 = "ScreenCapture" ascii //weight: 1
        $x_1_7 = "keyloggerActive" ascii //weight: 1
        $x_1_8 = "walletGrabber" ascii //weight: 1
        $x_1_9 = "BrowserDataExtractor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_OctoRat_HR_2147958834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OctoRat.HR!MTB"
        threat_id = "2147958834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OctoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e b6 00 00 0a 72 e6 31 00 70 16 6f bb 00 00 0a de 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


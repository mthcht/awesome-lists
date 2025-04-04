rule Worm_MSIL_NWorm_G_2147742428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/NWorm.G!MTB"
        threat_id = "2147742428"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W0rm.exe" ascii //weight: 1
        $x_1_2 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 1
        $x_1_3 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_4 = "/C choice /C Y /N /D Y /T 1 & Del" ascii //weight: 1
        $x_1_5 = "runFile" ascii //weight: 1
        $x_1_6 = "pongPing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_MSIL_NWorm_GA_2147744784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/NWorm.GA!MTB"
        threat_id = "2147744784"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W0rm.exe" ascii //weight: 1
        $x_1_2 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 1
        $x_1_3 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_4 = "/C choice /C Y /N /D Y /T 1 & Del" ascii //weight: 1
        $x_1_5 = "ExecutionPolicy Bypass -WindowStyle Hidden -NoExit -File" ascii //weight: 1
        $x_1_6 = "runFile" ascii //weight: 1
        $x_1_7 = "pongPing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_MSIL_NWorm_NIT_2147937964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/NWorm.NIT!MTB"
        threat_id = "2147937964"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {14 0a 73 1d 00 00 0a 0b 07 28 1e 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 07 6f ?? 00 00 0a 73 22 00 00 0a 0c 08 06 6f ?? 00 00 0a 08 04 6f ?? 00 00 0a 08 05 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 13 04 08 6f ?? 00 00 0a 11 04 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {28 18 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


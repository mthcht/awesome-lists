rule Trojan_MSIL_XenoRat_RPX_2147898899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRat.RPX!MTB"
        threat_id = "2147898899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xeno rat client" wide //weight: 1
        $x_1_2 = "AntivirusProduct" wide //weight: 1
        $x_1_3 = "choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
        $x_1_4 = "nothingset" wide //weight: 1
        $x_1_5 = "schtasks.exe" wide //weight: 1
        $x_1_6 = "Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_7 = "delete /tn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRat_SG_2147900905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRat.SG!MTB"
        threat_id = "2147900905"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cuckoomon.dll" ascii //weight: 1
        $x_1_2 = "XenoUpdateManager" wide //weight: 1
        $x_1_3 = "/query /v /fo csv" wide //weight: 1
        $x_1_4 = "xeno rat client.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_XenoRat_RHB_2147926756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRat.RHB!MTB"
        threat_id = "2147926756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Xeno-rat" wide //weight: 3
        $x_1_2 = "Live Microphone" wide //weight: 1
        $x_1_3 = "Key Logger" wide //weight: 1
        $x_1_4 = "Screen Control" wide //weight: 1
        $x_1_5 = "Uac Bypass" wide //weight: 1
        $x_1_6 = "xeno rat client.exe" wide //weight: 1
        $x_1_7 = "sent the kill command" wide //weight: 1
        $x_1_8 = "InfoGrab.zip" wide //weight: 1
        $x_2_9 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30 00 00 78 1c 00 00 48 03 00 00 00 00 00 5e 97 1c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRat_AXN_2147927565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRat.AXN!MTB"
        threat_id = "2147927565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 2b 41 09 6f ?? 00 00 0a 13 04 00 11 04 72 ?? 02 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 06 11 05 6f ?? 00 00 0a 16 fe 01 13 06 11 06 2c 0b 00 06 11 05 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRat_AXE_2147928137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRat.AXE!MTB"
        threat_id = "2147928137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 18 58 6f ?? 00 00 0a 28 ?? 00 00 06 1e 62 09 60 0d 02 08 19 58 6f ?? 00 00 0a 28 ?? 00 00 06 1f 0c 62 09 60 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRat_AXE_2147928137_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRat.AXE!MTB"
        threat_id = "2147928137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 2b 2c 08 6f ?? 00 00 0a 25 72 ?? 02 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 06 09 6f ?? 00 00 0a 2d 07 06 09 6f ?? 00 00 0a 6f ?? 00 00 0a 08 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRat_SLTR_2147941503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRat.SLTR!MTB"
        threat_id = "2147941503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7b 0f 00 00 04 2c 01 2a 02 17 7d 0f 00 00 04 72 18 02 00 70 18 73 26 00 00 0a 0a 02 06 28 5c 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


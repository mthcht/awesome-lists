rule Trojan_MSIL_ShadowRecruit_GVA_2147973613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShadowRecruit.GVA!MTB"
        threat_id = "2147973613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShadowRecruit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "-WindowStyle Hidden -ExecutionPolicy Bypass -Command" wide //weight: 1
        $x_1_2 = "Invoke-WebRequest" wide //weight: 1
        $x_1_3 = "://38.242.157.89/file.pdf" wide //weight: 1
        $x_1_4 = "Start-Process" wide //weight: 1
        $x_1_5 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 [0-48] 2e 00 70 00 64 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


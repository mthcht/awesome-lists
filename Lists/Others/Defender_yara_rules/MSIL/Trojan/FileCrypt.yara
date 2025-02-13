rule Trojan_MSIL_FileCrypt_GA_2147929713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCrypt.GA!MTB"
        threat_id = "2147929713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 04 11 06 61 13 10 08 11 0a 11 10}  //weight: 3, accuracy: High
        $x_1_2 = "LmJzcw==" wide //weight: 1
        $x_1_3 = "CallWindowProcA" ascii //weight: 1
        $x_1_4 = "{11111-22222-10009-11111}" wide //weight: 1
        $x_1_5 = "{11111-22222-10009-11112}" wide //weight: 1
        $x_1_6 = "Debugger Detected" wide //weight: 1
        $x_1_7 = "{11111-22222-10001-00001}" wide //weight: 1
        $x_1_8 = "{11111-22222-10001-00002}" wide //weight: 1
        $x_1_9 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_10 = "file:///" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


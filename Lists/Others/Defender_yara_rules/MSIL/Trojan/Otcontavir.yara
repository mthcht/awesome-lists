rule Trojan_MSIL_Otcontavir_A_2147711164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Otcontavir.A"
        threat_id = "2147711164"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Otcontavir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {3a 00 2f 00 2f 00 6c 00 61 00 6c 00 61 00 78 00 2e 00 63 00 61 00 74 00 2f 00 [0-16] 2f 00 75 00 70 00 2e 00 70 00 68 00 70 00}  //weight: 4, accuracy: Low
        $x_2_2 = "OutlookContactsViewer" ascii //weight: 2
        $x_1_3 = "UploadEmailList" ascii //weight: 1
        $x_1_4 = "RedemptionLoader" ascii //weight: 1
        $x_1_5 = "ProcesEmailBody" ascii //weight: 1
        $x_1_6 = "GetMailFromAllAccount" ascii //weight: 1
        $x_1_7 = "GetMailsFromHeaders" ascii //weight: 1
        $x_1_8 = "=====START-LIST-FROM-CONTACTS=====" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


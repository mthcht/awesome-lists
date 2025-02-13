rule Trojan_MSIL_Yakbeex_MBK_2147837889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Yakbeex.MBK!MTB"
        threat_id = "2147837889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yakbeex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 26 11 04 6f ?? 00 00 0a 00 20 88 13 00 00 28 ?? 00 00 0a 00 28 ?? 00 00 0a 72 00 02 00 70}  //weight: 3, accuracy: Low
        $x_3_2 = "attachments/884969220813754371/88" ascii //weight: 3
        $x_3_3 = "fiiirrst.txt" ascii //weight: 3
        $x_3_4 = "pad.exe" ascii //weight: 3
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "GetTempFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Yakbeex_NZQ_2147838090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Yakbeex.NZQ!MTB"
        threat_id = "2147838090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yakbeex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 2a 02 00 70 6f ?? 00 00 0a 00 25 72 40 02 00 70 6f 15 00 00 0a 00 25 16 6f 16 00 00 0a 00 25 17 6f 17 00 00 0a 00 25 17}  //weight: 1, accuracy: Low
        $x_1_2 = "501e3fdc-575d-492e-90bc-703fb6280ee2" ascii //weight: 1
        $x_1_3 = "DisableAntiSpyware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Yakbeex_PSEE_2147899361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Yakbeex.PSEE!MTB"
        threat_id = "2147899361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yakbeex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 17 64 0a 07 06 59 1f 1f 64 13 04 07 06 11 04 17 59 5f 59 0b 08 17 62 17 11 04 59 60 0c 06 20 00 00 00 01 41 15 00 00 00 07 1e 62 02 7b 3e 00 00 04 6f 9c 00 00 0a d2 60 0b 06 1e 62 0a 09 17 59 0d 09 16}  //weight: 5, accuracy: High
        $x_1_2 = "ComputeHash" ascii //weight: 1
        $x_1_3 = "GetHashCode" ascii //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


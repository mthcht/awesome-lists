rule Trojan_MSIL_XpertRat_MA_2147795094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XpertRat.MA!MTB"
        threat_id = "2147795094"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XpertRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadData" ascii //weight: 1
        $x_1_2 = "GetTypes" ascii //weight: 1
        $x_1_3 = "https://store2.gofile.io/download/658884da-8dd7-4781-9455-8aaf61fcb244/Atftigkvqscpv.dll" ascii //weight: 1
        $x_1_4 = "Utiteqzllhwefrwpjya" ascii //weight: 1
        $x_1_5 = "set_FileName" ascii //weight: 1
        $x_1_6 = "Start-Sleep -Seconds" ascii //weight: 1
        $x_1_7 = "LoginStatus" ascii //weight: 1
        $x_1_8 = "CallNextHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XpertRat_MB_2147796707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XpertRat.MB!MTB"
        threat_id = "2147796707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XpertRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 72 0b 00 00 70 6f ?? ?? ?? 0a 25 72 21 00 00 70 6f ?? ?? ?? 0a 25 17 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
        $x_1_4 = "QueryRequest" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "CheckRequest" ascii //weight: 1
        $x_1_7 = "get_FullName" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


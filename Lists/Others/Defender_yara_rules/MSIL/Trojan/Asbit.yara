rule Trojan_MSIL_Asbit_SP_2147837217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Asbit.SP!MTB"
        threat_id = "2147837217"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Asbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FszgaEeGiiDN" ascii //weight: 1
        $x_1_2 = "RufnlQtvhJbc" ascii //weight: 1
        $x_1_3 = "L2xvYWRlci5jb3JlP189" wide //weight: 1
        $x_1_4 = "dXNpbmcgU3lzdGVtLlJlZmxlY3Rpb247CnB1YmxpYyBjbGFzcyBQcm9ncmFtIHsKICAgIHB1YmxpYyBQcm9ncmFtKHN0cmluZyBzLCBwYX" wide //weight: 1
        $x_1_5 = "JhbXMgb2JqZWN0W10gYXJncyl7CiAgICAgICAgQXNzZW1ibHkuTG9hZChuZXcgU3lzdGVtLk5ldC5XZWJDbGllbnQoKS5Eb3dubG9hZERhd" wide //weight: 1
        $x_1_6 = "GEocykpLkNyZWF0ZUluc3RhbmNlKCJQcm9ncmFtIiwgdHJ1ZSwgQmluZGluZ0ZsYWdzLkNyZWF0ZUluc3RhbmNlLCBudWxsLCBhcmdzLCBud" wide //weight: 1
        $x_1_7 = "WxsLCBudWxsKTsKICAgIH0KfQ==" ascii //weight: 1
        $x_1_8 = "cmVnYXNtLmV4ZQ==" wide //weight: 1
        $x_1_9 = "aHR0cHM6Ly9yZGxpdGUuY29tLw==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Asbit_HNS_2147906774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Asbit.HNS!MTB"
        threat_id = "2147906774"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Asbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 00 65 00 78 00 65 00 00 05 36 00 34 00 [0-4] 0d 2f 00 75 00 20 00 7b 00 30 00 7d 00 00 ?? 68 00 74 00 74 00 70 00}  //weight: 2, accuracy: Low
        $x_2_2 = {73 68 66 6f 6c 64 65 72 2e 64 6c 6c [0-32] 47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d}  //weight: 2, accuracy: Low
        $x_2_3 = {53 79 73 74 65 6d 2e 54 65 78 74 22 00 [0-34] 53 74 61 72 74 [0-21] 57 65 62 52 65 71 75 65 73 74}  //weight: 2, accuracy: Low
        $x_2_4 = "GetRuntimeDirectory" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


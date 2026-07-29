rule Trojan_MSIL_SecTopRAT_DA_2147974725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SecTopRAT.DA!MTB"
        threat_id = "2147974725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SecTopRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "'&(&*)+).-0/1/32427686>=?=@=EDGFHFIHJFKFLFMFNFOFPFQFRFSFTFUFXWYWZW[W\\W]W^W_W`WaWbW" wide //weight: 1
        $x_1_2 = {a5 03 c9 03 e9 03 fc 03 0d 04 1f 04 38 04 84 04 99 04 b1 04 0f 05 35 05 58 05 3f 06 46 06 84 06 ad 06 bc 06 c7 06 d7 06 f3 06 34 07 5b 07 82 07 9d 07 c9 07 fa 07 3e 08 9b 08 1f 09 55 09 67 09 6e 09 8a 09 98 09 b3 09 ce 09 e6 09 fb 09 1f 0a 3c 0a 6d 0a 7b 0b d3 0b 00 0c 1b 0c 52 0c 88 0c ae 0c 17 0d 1c 0d 74 0d 8a 0d 9b 0d ac 0d d5 0d f0 0d 3f 0e 4c 0e 7a 0e a0 0e b6 0e c2 0e d6 0e ea 0e f9 0e 0e 0f 14 0f 3c 0f 5d 0f 7c 0f cd 0f 44 10 e8 10 26 11 40 11 73 11 81 11 1d 12 56 12 89 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


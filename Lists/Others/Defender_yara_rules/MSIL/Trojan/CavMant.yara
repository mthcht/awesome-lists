rule Trojan_MSIL_CavMant_DA_2147973272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CavMant.DA!MTB"
        threat_id = "2147973272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CavMant"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t)w(Kcg(YXZkN)G(ZIg(KjZjt)K(ZLZht)QINij(Y7Zit)S(K*ZkN)K(YfZkN)F(ZIg(" wide //weight: 1
        $x_1_2 = {20 00 00 0d 30 00 20 00 6d 00 69 00 6e 00 73 00 00 15 7b 00 30 00 7d 00 20 00 64 00 61 00 79 00 7b 00 31 00 7d 00 00 03 73 00 00 17 7b 00 30 00 7d 00 20 00 68 00 6f 00 75 00 72 00 7b 00 31 00 7d 00 00 15 7b 00 30 00 7d 00 20 00 6d 00 69 00 6e 00 7b 00 31 00 7d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


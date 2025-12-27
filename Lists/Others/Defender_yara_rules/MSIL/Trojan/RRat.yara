rule Trojan_MSIL_RRat_PGRR_2147957696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RRat.PGRR!MTB"
        threat_id = "2147957696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "0104202319918KLDFIJDRFOGZKAFREXRXHDZGFXHAKHEAKXAGKGDAHKAYDLFGKDOHZFZATGZFDLFXHDEZJGZGHDPFQLAGXGFJDZFKAGZDXFPFGFHLZKGHZHFHLDJA" ascii //weight: 3
        $x_3_2 = "178973406770.My.Resources" ascii //weight: 3
        $x_3_3 = "o411366791f204c459ff919e0401e89e1" ascii //weight: 3
        $x_1_4 = "15686204.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RRat_ARR_2147958025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RRat.ARR!MTB"
        threat_id = "2147958025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "m_d31c734eae4c48c0bdb21037a75a82ff" ascii //weight: 5
        $x_3_2 = "<Module>{9ea83670-81f5-42b9-90c2-749f22f5e496}" ascii //weight: 3
        $x_2_3 = "Customer.Descriptor" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RRat_LMK_2147958065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RRat.LMK!MTB"
        threat_id = "2147958065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {45 07 00 00 00 8b 00 00 00 7b 00 00 00 24 00 00 00 b5 00 00 00 05 00 00 00 c4 00 00 00 d7 00 00 00 38 86 00 00 00 38 cd 00 00 00 20 06 00 00 00 7e 37 02 00 04 39 c6 ff ff ff 26 20 05 00 00 00 38 bb ff ff ff 03 14 20 fb ee 4f 23 65 20 ad 18 b0 dc 61 28 4b 04 00 06 17 8d 08 00 00 01 13 01 11 01 16 1f 6b}  //weight: 10, accuracy: High
        $x_20_2 = {11 00 17 9a 20 66 d9 2f 02 20 f0 3c e6 ce 61 20 ae ef c9 cc 61 28 4b 04 00 06 16 7e 5a 02 00 04 28 ea 08 00 06 16 fe 01 11 00 18 9a 7e 7c 00 00 04 7e 4e 02 00 04 28 be 08 00 06}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RRat_AMTB_2147958344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RRat!AMTB"
        threat_id = "2147958344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "10566d86-640f-4322-8873-bc4fbae63d99" ascii //weight: 2
        $x_2_2 = "kLjw4iIsCLsZtxc4lksN0j" ascii //weight: 2
        $x_2_3 = "3e4f9a35-89df-4a65-9ab7-0eefa03309b6" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RRat_AMTB_2147958344_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RRat!AMTB"
        threat_id = "2147958344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "38163989.exe" ascii //weight: 2
        $x_2_2 = "605557084825.My.Resources" ascii //weight: 2
        $x_2_3 = "u9ec052bdaf784bba9d85a77ff5528a3a" ascii //weight: 2
        $x_2_4 = "kLjw4iIsCLsZtxc4lksN0j" ascii //weight: 2
        $x_2_5 = "DisableAuthentication" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_XMRig_A_2147903170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XMRig.A!MTB"
        threat_id = "2147903170"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "XMR_GO" ascii //weight: 2
        $x_2_2 = "POOL_XMR" ascii //weight: 2
        $x_2_3 = "URLPANEL" ascii //weight: 2
        $x_1_4 = "IsAdministrator" ascii //weight: 1
        $x_1_5 = "ManagementObjectSearcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XMRig_SPCB_2147929580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XMRig.SPCB!MTB"
        threat_id = "2147929580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {05 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 1e 2b 20}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XMRig_SWA_2147937144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XMRig.SWA!MTB"
        threat_id = "2147937144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 6f 0e 00 00 0a 0b 06 6f ?? 00 00 0a 07 28 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 7e 02 00 00 04 25 3a 17 00 00 00 26 7e 01 00 00 04 fe 06 06 00 00 06 73 16 00 00 0a 25 80 02 00 00 04 28 ?? 00 00 2b 0d 09 14 28 ?? 00 00 0a 39 4b 00 00 00 09 72 8d 00 00 70 1f 1c 6f ?? 00 00 0a 13 0d 11 0d 14 28 ?? 00 00 0a 39 2f 00 00 00 14 13 0e 11 0d 6f ?? 00 00 0a 3a 08 00 00 00 09 28 ?? 00 00 0a 13 0e 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XMRig_GRR_2147946171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XMRig.GRR!MTB"
        threat_id = "2147946171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 67 00 00 70 28 14 00 00 0a 13 00 38 00 00 00 00 72 c1 00 00 70 28 14 00 00 0a 13 01 38 1a 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


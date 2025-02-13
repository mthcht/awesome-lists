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


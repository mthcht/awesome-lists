rule Ransom_Win64_Cephalus_GTB_2147950829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cephalus.GTB!MTB"
        threat_id = "2147950829"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cephalus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Tox:91C24" ascii //weight: 2
        $x_2_2 = "we have stolen confidential data from your intranet" ascii //weight: 2
        $x_2_3 = "We're Cephalus," ascii //weight: 2
        $x_2_4 = "your intranet has been compromised by us" ascii //weight: 2
        $x_2_5 = "Embrace it and pay us" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


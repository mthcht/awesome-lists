rule Trojan_Win64_Minix_GVA_2147974858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Minix.GVA!MTB"
        threat_id = "2147974858"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Minix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeShutdownPrivilege" wide //weight: 1
        $x_1_2 = "laudanosine" wide //weight: 1
        $x_1_3 = "strmkilden afbrerens batikfarvningen" wide //weight: 1
        $x_1_4 = "lastvognen immuniseringerne" wide //weight: 1
        $x_1_5 = "irreversibleness" wide //weight: 1
        $x_1_6 = "ripley" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


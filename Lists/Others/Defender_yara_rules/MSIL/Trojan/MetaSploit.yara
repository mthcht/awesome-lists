rule Trojan_MSIL_MetaSploit_A_2147838565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MetaSploit.A!MTB"
        threat_id = "2147838565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MetaSploit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "skjfklsdhljkfhgjlkasdfhgjskdfhgjksdfhgjj" wide //weight: 2
        $x_2_2 = "sakgdhfasgfdkhjasdgfhajsgdfhjasgdvhjxzcgvbhjbehaufgahjsdfgvchjcxbv" wide //weight: 2
        $x_2_3 = "DFLGJDFLGBJNDFLNBLDFNSKFGBNMSLDFB" wide //weight: 2
        $x_1_4 = "CreateThread" ascii //weight: 1
        $x_1_5 = "WaitForSingleObject" ascii //weight: 1
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


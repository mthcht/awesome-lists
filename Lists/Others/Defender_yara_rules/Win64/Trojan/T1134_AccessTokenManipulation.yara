rule Trojan_Win64_T1134_AccessTokenManipulation_A_2147846089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1134_AccessTokenManipulation.A"
        threat_id = "2147846089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1134_AccessTokenManipulation"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "privilege::debug" wide //weight: 10
        $x_10_2 = "privilege::driver" wide //weight: 10
        $x_10_3 = "privilege::security" wide //weight: 10
        $x_10_4 = "privilege::backup" wide //weight: 10
        $x_10_5 = "privilege::tcb" wide //weight: 10
        $x_10_6 = "privilege::restore" wide //weight: 10
        $x_10_7 = "privilege::id " wide //weight: 10
        $x_10_8 = "privilege::name " wide //weight: 10
        $x_10_9 = "token::run" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


rule Trojan_MSIL_Phonzy_MK_2147968946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Phonzy.MK!MTB"
        threat_id = "2147968946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phonzy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "<StartRAT>b__0" ascii //weight: 10
        $x_5_2 = "<FirefoxSteal>b__0" ascii //weight: 5
        $x_3_3 = "<KillBrowserProcesses>d__2" ascii //weight: 3
        $x_2_4 = "<CollectBrowserStats>b__1_0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


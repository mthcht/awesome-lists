rule Trojan_Win32_Banavkill_A_2147723759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banavkill.A"
        threat_id = "2147723759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banavkill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "E30032FF44F55181B06D82AF68FB4BEB6F82F53BF735629A409F45FD3CE61AB02EE630FA38CB172572B860" ascii //weight: 2
        $x_2_2 = "A142F03C98583F93A253E816C21EAD4883B681B548E37EAC4986A78DBF608E9833EF6B89FE3FF73C968AEB" ascii //weight: 2
        $x_2_3 = "360A7DB815DE5BF93AE454F11FA537E167FD37F136C01B62953BFF2DCE74ABDE39" ascii //weight: 2
        $x_2_4 = "D9A99E5DFC072EA95ADD062FE8" ascii //weight: 2
        $x_2_5 = "94A544F11725DA73C6BF72D60A4C9740995995AE999133C169FD0A37CD" ascii //weight: 2
        $x_1_6 = "190E1F2245EE19B3739E5D3935A82DD57E839358EE3B98E172D26CAA73904998CC4988B073B5" ascii //weight: 1
        $x_1_7 = "C24DD96987BABC18D9092ED30CB71328AC4BE80C2BDE7FB46FD013C9A6488AD9" ascii //weight: 1
        $x_1_8 = "CC7BEA0DB642E0748CB044ED2AB0C97FC477BA76BF6CE850D17789A4959E4984C06DEB03082FC874E20E3451E3162A" ascii //weight: 1
        $x_1_9 = "DF6EF836A842E472E61FC26894CB063C98AD74B64CF45E9A8FC71530" ascii //weight: 1
        $x_1_10 = "20313CC125CE79D3133EFA5FEF6FE30EB64AF632F70543E31003123DF21CC01340F565EB68FB180240F0588E52FD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Themidapacked_RH_2147809233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Themidapacked.RH!MTB"
        threat_id = "2147809233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Themidapacked"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "UZkkmmkkX:" ascii //weight: 2
        $x_1_2 = "!).//EEFFFHFHHHFH>FDD.+#" ascii //weight: 1
        $x_1_3 = "_!6hmssrtrrrtqqmI%" ascii //weight: 1
        $x_1_4 = ";FSXXYYXXR." ascii //weight: 1
        $x_2_5 = "Spy.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


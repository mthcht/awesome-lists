rule Trojan_Win64_Yogi_GVA_2147976307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.GVA!MTB"
        threat_id = "2147976307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.amtppol" ascii //weight: 1
        $x_1_2 = "main..inittask" ascii //weight: 1
        $x_1_3 = "main.Ncfsxqiifgcfbdy" ascii //weight: 1
        $x_1_4 = "main.jdzyznjfpka" ascii //weight: 1
        $x_1_5 = "main.pfdviozmtpnsvegtsw" ascii //weight: 1
        $x_1_6 = "main.(*TIOAS).zbadbpulk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


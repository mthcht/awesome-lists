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

rule Trojan_Win64_Yogi_SI_2147976750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.SI!MTB"
        threat_id = "2147976750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {ff 15 7d d5 00 00 be 01 00 00 00 48 8d 0d b9 4d 01 00 44 8b c6 89 05 d0 92 01 00 33 d2 ff 15 78 d5 00 00 48 89 05 b9 92 01 00 48 85 c0 0f 84 8b 01 00 00 8b 15 b2 92 01 00 48 8d 88 00 10 00 00 4c 8d 4c 24 48 48 89 0d a7 92 01 00 41 b8 08 00 00 00 89 7c 24 48 ff 15 c7 d4 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {0f 10 05 0f 4e 01 00 0f b7 05 20 4e 01 00 45 33 c9 48 89 7c 24 30 45 33 c0 0f 11 01 ba 00 00 00 80 89 7c 24 28 f2 0f 10 05 f9 4d 01 00}  //weight: 3, accuracy: High
        $x_1_3 = "colorui.dll" ascii //weight: 1
        $x_1_4 = "LaunchColorCpl" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_SpectreRat_ASP_2147932018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpectreRat.ASP!MTB"
        threat_id = "2147932018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpectreRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B3C830CA-4433-CC3A-6737" ascii //weight: 1
        $x_2_2 = "CullinetProgram" ascii //weight: 2
        $x_3_3 = "manjitaugustuswaters.com" ascii //weight: 3
        $x_4_4 = "76E894005c2DE86E40b032a0931D2ABC05C6eB36ACb1C18F5b640aD24Bbc9454" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


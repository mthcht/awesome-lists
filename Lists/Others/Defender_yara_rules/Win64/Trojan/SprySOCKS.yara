rule Trojan_Win64_SprySOCKS_GVA_2147971806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SprySOCKS.GVA!MTB"
        threat_id = "2147971806"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SprySOCKS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 45 33 c9 41 b8 02 00 00 00 33 d2 48 8b 8c 24 a8 00 00 00 ff 15 a4 73 01 00 48 89 84 24 a0 00 00 00 48 83 bc 24 a0 00 00 00 00 75 05 e9 ec 08 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 45 33 c0 ba 04 00 00 00 48 8b 8c 24 a0 00 00 00 ff 15 12 73 01 00 48 89 44 24 68 48 83 7c 24 68 00 75 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SprySOCKS_GVC_2147971807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SprySOCKS.GVC!MTB"
        threat_id = "2147971807"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SprySOCKS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uXQLESMXGaRMs6BL" ascii //weight: 1
        $x_1_2 = "\\DriverMemoryLoadDriver\\x64\\Release\\DriverMemoryLoadDriver.pdb" ascii //weight: 1
        $x_1_3 = "Windows\\Fonts\\KW1B5206BDC1743FP.dat" wide //weight: 1
        $x_1_4 = "RtlImageDirectoryEntryToData" wide //weight: 1
        $x_1_5 = "\\Driver\\MmRose" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


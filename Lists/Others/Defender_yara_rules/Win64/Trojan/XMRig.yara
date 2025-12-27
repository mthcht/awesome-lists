rule Trojan_Win64_XMRig_CCAN_2147890127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XMRig.CCAN!MTB"
        threat_id = "2147890127"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 d0 48 98 48 8d 15 ?? ?? ?? ?? 40 32 2c 02 41 88 2c 3c 48 83 c7 01 49 39 fd 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XMRig_GA_2147929548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XMRig.GA!MTB"
        threat_id = "2147929548"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.e1Bu7FURlcwCRDw" ascii //weight: 1
        $x_1_2 = "main.UGJIJ1Cuv3YDR" ascii //weight: 1
        $x_1_3 = "main.UIehToRIXbAGgw" ascii //weight: 1
        $x_1_4 = "go:itab.*net.IPAddr,net.Addr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XMRig_RK_2147939292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XMRig.RK!MTB"
        threat_id = "2147939292"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {30 4c 04 3e 48 ff c0 48 83 f8 0c 73 06 8a 4c 24 3d}  //weight: 3, accuracy: High
        $x_2_2 = "PzLFbmBmYVZXbjd2ms94dMpoVW5jZmFWE243dmUweHRyaFVuY2Z" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XMRig_WQ_2147939454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XMRig.WQ!MTB"
        threat_id = "2147939454"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OmNom.exe" ascii //weight: 1
        $x_1_2 = "Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_3 = "Defender-Ausnahmen" ascii //weight: 1
        $x_1_4 = "ubrin.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XMRig_SD_2147940855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XMRig.SD!MTB"
        threat_id = "2147940855"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 05 b7 da 00 00 ee d9 d2 73 e8 ?? ?? ?? ?? c7 05 a8 da 00 00 ec 07 75 ec e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XMRig_GDZ_2147959472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XMRig.GDZ!MTB"
        threat_id = "2147959472"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 47 10 44 32 1c 10 45 88 1c 0a 0f b6 03 a8 01 41 0f 94 c2 0f 85 ?? ?? ?? ?? d1 e8 4c 89 c1 49 39 c0 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


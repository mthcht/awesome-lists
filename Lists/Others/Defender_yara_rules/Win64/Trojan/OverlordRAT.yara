rule Trojan_Win64_OverlordRAT_AA_2147977891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OverlordRAT.AA!MTB"
        threat_id = "2147977891"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OverlordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {0f b6 d2 0f b6 94 14 ?? ?? ?? ?? 30 54 0b ff 48 8d 14 0f 48 ff c2 48 ff c1 48 83 fa}  //weight: 16, accuracy: Low
        $x_4_2 = "badata_x64.dll" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OverlordRAT_AB_2147977892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OverlordRAT.AB!MTB"
        threat_id = "2147977892"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OverlordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {46 0f b6 8c 0c ?? ?? ?? ?? 45 30 08 49 ff c0 fe c2 49 39 c0 72}  //weight: 16, accuracy: Low
        $x_4_2 = "badata_x64.dll" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OverlordRAT_AG_2147980005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OverlordRAT.AG!MTB"
        threat_id = "2147980005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OverlordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 8a 44 14 ?? 44 30 04 0f 48 ff c2 48 ff c1 eb}  //weight: 5, accuracy: Low
        $x_4_2 = {01 da c1 c3 05 31 d3 01 c1 c1 c0 08 31 c8 01 d9 c1 c2 10 01 c2 c1 c0 0d c1 c3 07 31 d0 31 cb c1 c1 10 eb d7}  //weight: 4, accuracy: High
        $x_1_3 = "VMwareVMwareXenVMMXenVMMprl hypervVBoxVBoxVBoxbhyve bhyve" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OverlordRAT_A_2147981252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OverlordRAT.A!AMTB"
        threat_id = "2147981252"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OverlordRAT"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/rat/result" ascii //weight: 1
        $x_1_2 = "/rat/poll" ascii //weight: 1
        $x_1_3 = "loot_%s.zip" ascii //weight: 1
        $x_1_4 = "hs_keys.dat" ascii //weight: 1
        $x_1_5 = "hs_vss.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


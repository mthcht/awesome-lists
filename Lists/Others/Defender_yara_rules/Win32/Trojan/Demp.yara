rule Trojan_Win32_Demp_EH_2147829635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Demp.EH!MTB"
        threat_id = "2147829635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Demp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 16 8d 76 01 0f b6 44 37 ff 02 c2 02 d8 0f b6 c3 03 c8 ff 8d f8 fe ff ff 0f b6 01 88 46 ff 88 11 8b 8d f4 fe ff ff 75 d7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Demp_KAA_2147852101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Demp.KAA!MTB"
        threat_id = "2147852101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Demp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 04 0f 8d 49 01 32 c2 80 c2 05 88 41 ff 83 ee 01 75 ed}  //weight: 10, accuracy: High
        $x_1_2 = "LivingOffTheLand.pdb" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


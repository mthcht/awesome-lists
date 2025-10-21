rule Trojan_Win64_RomCom_GVA_2147955714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RomCom.GVA!MTB"
        threat_id = "2147955714"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RomCom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 10 48 ff c0 49 83 c1 02 49 83 f9 18 0f 84}  //weight: 2, accuracy: High
        $x_1_2 = {45 31 c0 41 80 fa 2b 41 0f 94 c0 49 01 c8 47 0f b6 5c 01 fe 41 8d 73 bf 83 e6 ?? 83 c6 0a 41 8d 53 d0 41 83 fb 3a 0f 43 d6 83 fa 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


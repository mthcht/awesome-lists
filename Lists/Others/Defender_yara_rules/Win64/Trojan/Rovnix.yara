rule Trojan_Win64_Rovnix_2147691040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rovnix"
        threat_id = "2147691040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f be 44 24 30 48 8b 0c 24 48 8b 54 24 20 48 03 d1 48 8b ca 0f be 09 33 c8 8b c1 48 8b 0c 24 48 8b 54 24 20 48 03 d1 48 8b ca 88 01 eb bc}  //weight: 2, accuracy: High
        $x_2_2 = {0f b7 44 24 30 48 8b 4c 24 20 48 8b 14 24 0f b7 0c 51 33 c8 8b c1 48 8b 4c 24 20 48 8b 14 24 66 89 04 51 eb c5}  //weight: 2, accuracy: High
        $x_2_3 = "BOOTKIT_DLL" ascii //weight: 2
        $x_1_4 = "BN21Rc0LqZA9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


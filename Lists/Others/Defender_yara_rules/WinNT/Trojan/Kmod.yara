rule Trojan_WinNT_Kmod_A_2147629884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Kmod.A"
        threat_id = "2147629884"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Kmod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 6a 04 53 ff 15 ?? ?? ?? ?? 6a 04 6a 04 57 ff 15 ?? ?? ?? ?? c7 45 fc fe ff ff ff 8b 13 a1 ?? ?? ?? ?? 39 50 08 77 ?? c7 45 e4 0d 00 00 c0 83 66 1c 00 8b 45 e4 89 46 18 32 d2 8b ce ff 15 ?? ?? ?? ?? 8b 45 e4}  //weight: 1, accuracy: Low
        $x_1_2 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 07 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Kmod_C_2147633448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Kmod.C"
        threat_id = "2147633448"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Kmod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 03 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: High
        $x_1_2 = {83 4d fc ff 8b 45 e0 8b 10 a1 ?? ?? ?? ?? 39 50 08 77 ?? c7 45 e4 0d 00 00 c0}  //weight: 1, accuracy: Low
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


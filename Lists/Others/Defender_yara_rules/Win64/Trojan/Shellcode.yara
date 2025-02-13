rule Trojan_Win64_Shellcode_AMMH_2147909692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shellcode.AMMH!MTB"
        threat_id = "2147909692"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 d0 44 0f b6 00 8b 85 ?? ?? ?? ?? 48 98 0f b6 4c 05 ?? 8b 85 ?? ?? ?? ?? [0-11] 48 01 d0 44 89 c2 31 ca 88 10 83 85 ?? ?? ?? ?? 01 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 48 98 48 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_TinplateLoader_B_2147919488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TinplateLoader.B!dha"
        threat_id = "2147919488"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TinplateLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7b 7d 6e 6a c7 84 24 ?? ?? ?? ?? 34 35 6b 64 c7 84 24 ?? ?? ?? ?? 61 64 61 30 c7 84 24 ?? ?? ?? ?? 73 6c 66 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


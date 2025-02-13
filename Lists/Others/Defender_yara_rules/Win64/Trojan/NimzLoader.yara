rule Trojan_Win64_NimzLoader_PA_2147779013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NimzLoader.PA!MTB"
        threat_id = "2147779013"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NimzLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fatal.nim" ascii //weight: 1
        $x_2_2 = {31 c0 48 89 ca 49 63 0c ?? 48 89 e6 8a 0c 0a 88 0c 04 48 ff c0 48 83 f8 ?? 75 ea 48 89 d7 b9 ?? ?? ?? ?? 31 c0 f3 a5 48 83 c4 ?? 5e 5f c3 31 c0 41 39 c0 7e ?? 44 8a 0c 02 44 30 0c 01 48 ff c0 eb ?? 31 c0 c3}  //weight: 2, accuracy: Low
        $x_2_3 = {48 89 ea 31 db eb [0-4] 40 30 7c 1e ?? 48 8b 16 48 39 da 76 ?? 48 89 f8 48 c1 f8 ?? 30 44 1e ?? 48 8b 16 48 39 d3 0f 83 ?? ?? ?? ?? 48 89 f8 48 c1 f8 ?? 30 44 1e ?? 48 8b 16 48 39 da 76 ?? 48 89 f8 48 83 c7 ?? 48 c1 f8 ?? 30 44 1e ?? 48 83 c3 ?? 48 39 dd 0f 8e ?? ?? ?? ?? 48 8b 16 48 39 d3 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


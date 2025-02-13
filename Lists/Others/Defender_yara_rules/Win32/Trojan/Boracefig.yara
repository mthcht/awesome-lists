rule Trojan_Win32_Boracefig_B_2147718381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boracefig.B!bit"
        threat_id = "2147718381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boracefig"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7c 24 18 76 0f 85 ?? ?? ?? ?? 80 7c 24 19 64 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {32 c2 66 0f b6 d2 66 c1 e7 08 66 0b fa 66 33 7c 24 14 88 44 24 0d}  //weight: 1, accuracy: High
        $x_2_3 = {8a 4c 14 30 8a c2 f6 ea 04 03 84 c9 74 0a 3a c8 74 06 32 c8 88 4c 14 30 42 81 fa ?? ?? ?? ?? 72}  //weight: 2, accuracy: Low
        $x_1_4 = "DELETE-TCB" ascii //weight: 1
        $x_1_5 = "Dir %dk (%d)" ascii //weight: 1
        $x_1_6 = "//%s/%5.5d.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


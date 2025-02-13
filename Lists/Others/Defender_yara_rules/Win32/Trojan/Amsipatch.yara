rule Trojan_Win32_Amsipatch_A_2147742693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amsipatch.A!!Amsipatch.A"
        threat_id = "2147742693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amsipatch"
        severity = "Critical"
        info = "Amsipatch: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {b8 57 00 07 80 c3 [0-144] 74 ?? 81 ?? 41 4d 53 49 75}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amsipatch_A_2147742693_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amsipatch.A!!Amsipatch.A"
        threat_id = "2147742693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amsipatch"
        severity = "Critical"
        info = "Amsipatch: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {b8 57 00 07 80 c2 18 00 [0-112] 74 ?? 81 ?? 41 4d 53 49 75}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win64_Settra_A_2147980169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Settra.A!ldr"
        threat_id = "2147980169"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Settra"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 3e 2d 00 0f 85 c4 00 00 00 66 81 7e 02 2d 00 0f 85 b8 00 00 00 66 81 7e 04 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 39 ca 0f 83 ?? 00 00 00 40 0f b6 04 16 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


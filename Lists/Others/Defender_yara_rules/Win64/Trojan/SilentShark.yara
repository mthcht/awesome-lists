rule Trojan_Win64_SilentShark_A_2147972751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilentShark.A"
        threat_id = "2147972751"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilentShark"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {50 73 53 65 74 43 72 65 61 74 65 50 72 6f 63 65 73 73 4e 6f 74 69 66 79 52 6f 75 74 69 6e 65 45 78 00}  //weight: 10, accuracy: High
        $x_1_2 = "GpTdbeVyNEJErQh" wide //weight: 1
        $x_1_3 = "dJpKRcKJaAHmBEJk" wide //weight: 1
        $x_1_4 = "OSvnOeEMDWBWdEqS" wide //weight: 1
        $x_1_5 = "UpknHIskgbaMtPtT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


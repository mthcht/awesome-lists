rule TrojanDropper_Win32_Dacic_DMX_2147978908_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dacic.DMX!MTB"
        threat_id = "2147978908"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "madium-bootstrap/" ascii //weight: 5
        $x_1_2 = "YYKgAJTLajIDgmxfn77lrg==" ascii //weight: 1
        $x_1_3 = "M1lArs78ssHiaOfNhk8AXw==" ascii //weight: 1
        $x_1_4 = "IjT3SCbiRQuadi/wa6yN7w==" ascii //weight: 1
        $x_3_5 = {67 00 65 00 74 00 6d 00 61 00 64 00 69 00 75 00 6d 00 2e 00 78 00 79 00 7a 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}


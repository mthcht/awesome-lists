rule Trojan_MSIL_Ulise_AAD_2147972891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ulise.AAD!AMTB"
        threat_id = "2147972891"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ulise"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 6c 69 76 65 72 2d 73 74 61 67 65 72 2d 32 30 32 [0-15] 2d 61 6d 64 36 34 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_2_2 = "TerminateProcess" ascii //weight: 2
        $x_2_3 = "Resolve server address and port..." ascii //weight: 2
        $x_2_4 = "Attempt to connect to the first resolved server address..." ascii //weight: 2
        $x_2_5 = "shutdown failed: %d" ascii //weight: 2
        $x_2_6 = "Injecting stage..." ascii //weight: 2
        $x_2_7 = "Executing stage..." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


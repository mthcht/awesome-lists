rule Trojan_Win64_Envdropper_DA_2147924487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Envdropper.DA!MTB"
        threat_id = "2147924487"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Envdropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Attempting lateral movement..." ascii //weight: 10
        $x_10_2 = "envdropper" ascii //weight: 10
        $x_1_3 = "Debugger or monitoring tool detected! Self-destructing..." ascii //weight: 1
        $x_1_4 = "Debugger detected! Exiting." ascii //weight: 1
        $x_1_5 = "Encryption and decryption completed." ascii //weight: 1
        $x_1_6 = "No virtualization or observation detected. Safe to continue." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


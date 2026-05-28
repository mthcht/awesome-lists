rule Trojan_Win64_GlassElevator_A_2147970398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GlassElevator.A!dha"
        threat_id = "2147970398"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GlassElevator"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YGEBJDJNRMDKXJyhbehKFDNFJENRoi" ascii //weight: 1
        $x_1_2 = " Direct Syscall-Based Reflective Hollowing" ascii //weight: 1
        $x_1_3 = " by @xaitax" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GlassElevator_B_2147970399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GlassElevator.B!dha"
        threat_id = "2147970399"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GlassElevator"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " YGEBJDJNRMDKXJyhbehKFDNFJENRoi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


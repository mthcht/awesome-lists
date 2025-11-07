rule Trojan_Win32_MalRecoveryDisable_AA_2147957007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalRecoveryDisable.AA"
        threat_id = "2147957007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalRecoveryDisable"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcdedit" wide //weight: 1
        $x_1_2 = "/set" wide //weight: 1
        $x_1_3 = "recoveryenabled no" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_RanuBot_AA_2147750908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RanuBot.AA!MTB"
        threat_id = "2147750908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RanuBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OzVw39yjF4RfsVcgmi6c/eYrahwfiLWrlP_ug-KBM/nuOCmPKFOG2BGYHbu1eA/NgrxeIRJRBOKkzs_VmFM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


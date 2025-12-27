rule Trojan_Win32_MalIgnoreFailure_AA_2147957008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalIgnoreFailure.AA"
        threat_id = "2147957008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalIgnoreFailure"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcdedit" wide //weight: 1
        $x_1_2 = "/set" wide //weight: 1
        $x_1_3 = "bootstatuspolicy" wide //weight: 1
        $x_1_4 = "ignoreallfailures" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


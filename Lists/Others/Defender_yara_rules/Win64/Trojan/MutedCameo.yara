rule Trojan_Win64_MutedCameo_A_2147978561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MutedCameo.A!ldr"
        threat_id = "2147978561"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MutedCameo"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "calcTheThings" ascii //weight: 1
        $x_1_2 = "pwndem" ascii //weight: 1
        $x_1_3 = "SetupETWBreakpoints" ascii //weight: 1
        $x_1_4 = "MySleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


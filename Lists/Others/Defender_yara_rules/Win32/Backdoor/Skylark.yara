rule Backdoor_Win32_Skylark_A_2147643370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Skylark.A"
        threat_id = "2147643370"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Skylark"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Skylark Server v" ascii //weight: 4
        $x_3_2 = "Trojan Management Agents Module." ascii //weight: 3
        $x_4_3 = "SkylarkCfg" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


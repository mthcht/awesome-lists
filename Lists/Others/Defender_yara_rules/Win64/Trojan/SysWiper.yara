rule Trojan_Win64_SysWiper_AB_2147972777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SysWiper.AB!MTB"
        threat_id = "2147972777"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR PC IS NOW SCRAP!" ascii //weight: 1
        $x_1_2 = "vssadmin delete shadows /all /quiet 2>nul" ascii //weight: 1
        $x_1_3 = "reg delete HKLM /f 2>nul" ascii //weight: 1
        $x_1_4 = "taskkill /f /im \"*\" 2>nul" ascii //weight: 1
        $x_1_5 = "R9D HACKED YOU PC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


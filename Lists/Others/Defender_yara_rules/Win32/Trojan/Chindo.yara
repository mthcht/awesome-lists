rule Trojan_Win32_Chindo_SP_2147753480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chindo.SP!MSR"
        threat_id = "2147753480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chindo"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Internet Explorer\\Main\\FeatureControl\\FEATURE_BROWSER_EMULATION" ascii //weight: 1
        $x_1_2 = "config.myloglist.top" ascii //weight: 1
        $x_2_3 = "\\Application Data\\YiYaZip\\" wide //weight: 2
        $x_1_4 = "MzYwVHJheS5leGU=" ascii //weight: 1
        $x_2_5 = "YiCompress_Update_Mutex" ascii //weight: 2
        $x_2_6 = "\\YiCompress\\Yiz.config" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


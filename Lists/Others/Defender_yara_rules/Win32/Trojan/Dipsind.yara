rule Trojan_Win32_Dipsind_A_2147708647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dipsind.A!!Dipsind.gen!dha"
        threat_id = "2147708647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dipsind"
        severity = "Critical"
        info = "Dipsind: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AOPSH03SK09POKSID7FF674PSLI91965" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Worm_Win32_Flukan_A_2147583562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Flukan.A"
        threat_id = "2147583562"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Flukan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Virus\\Flu-Ikan\\Flu_Ikan.vbp" wide //weight: 1
        $x_1_2 = "n1=/nick /remote on" wide //weight: 1
        $x_1_3 = "RavTimeXP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Flukan_C_2147649716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Flukan.C"
        threat_id = "2147649716"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Flukan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Flu_Ikan.vbp" wide //weight: 1
        $x_1_2 = "Timer_EnScript" ascii //weight: 1
        $x_1_3 = "tmr_reg_virus" ascii //weight: 1
        $x_1_4 = "infeksi_mirc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


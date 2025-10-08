rule Trojan_Win32_AggahMalspam_MK_2147954082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AggahMalspam.MK"
        threat_id = "2147954082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AggahMalspam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta.exe " ascii //weight: 1
        $x_1_2 = "vbscript:close(" ascii //weight: 1
        $x_1_3 = "Execute(" ascii //weight: 1
        $x_1_4 = "CreateObject(" ascii //weight: 1
        $x_1_5 = "wscript.Shell" ascii //weight: 1
        $x_1_6 = ").Run" ascii //weight: 1
        $x_1_7 = "winver.exe" ascii //weight: 1
        $n_1_8 = "9453e881-26a8-4973-ba2e-76269e901d0q" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


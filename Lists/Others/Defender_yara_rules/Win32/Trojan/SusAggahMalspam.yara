rule Trojan_Win32_SusAggahMalspam_MK_2147955547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusAggahMalspam.MK"
        threat_id = "2147955547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusAggahMalspam"
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
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Misleading_Win32_Chanicef_241974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Chanicef"
        threat_id = "241974"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Chanicef"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://www.dk-soft.org" wide //weight: 2
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_2_3 = "Advanced PC-Mechanic" ascii //weight: 2
        $x_2_4 = "http://www.efixpctools.com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


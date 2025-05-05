rule Trojan_Win32_Artoelo_BA_2147940642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Artoelo.BA"
        threat_id = "2147940642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Artoelo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ">nul & " ascii //weight: 1
        $x_1_2 = "\\windows\\temp\\" ascii //weight: 1
        $x_1_3 = "\\\\.\\pipe\\move" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


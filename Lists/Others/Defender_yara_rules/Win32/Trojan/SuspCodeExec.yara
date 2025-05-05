rule Trojan_Win32_SuspCodeExec_E_2147940644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspCodeExec.E"
        threat_id = "2147940644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCodeExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& pcalua.exe -a " ascii //weight: 1
        $x_1_2 = " -c \\\\.\\pipe\\move" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


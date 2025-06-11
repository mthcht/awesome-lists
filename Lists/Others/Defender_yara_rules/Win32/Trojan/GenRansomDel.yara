rule Trojan_Win32_GenRansomDel_BSA_2147943451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenRansomDel.BSA!MTB"
        threat_id = "2147943451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenRansomDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/C DEL /F /Q C:\\PROGRA" wide //weight: 10
        $x_1_2 = ".tmp >> NUL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_RDPCredDumping_C_2147830969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RDPCredDumping.C"
        threat_id = "2147830969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RDPCredDumping"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "tasklist.exe" wide //weight: 10
        $x_10_2 = "/M:rdpcorets.dll" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


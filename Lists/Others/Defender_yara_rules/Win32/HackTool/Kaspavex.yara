rule HackTool_Win32_Kaspavex_A_2147630948_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Kaspavex.A"
        threat_id = "2147630948"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Kaspavex"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "attrib +r +h +s \"C:\\Program Files\\Kaspersky Lab\\" ascii //weight: 1
        $x_1_2 = "reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\KasperskyLab\\LicStorage\" /f" ascii //weight: 1
        $x_1_3 = "reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\RNG\" /f" ascii //weight: 1
        $x_1_4 = "reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\SPC\\Certificates\" /f" ascii //weight: 1
        $x_2_5 = {68 ff 00 00 00 ff 15 ?? ?? 40 00 6a 32 68 ?? ?? 40 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 68 ?? ?? 40 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 e8 02 00 00 00 20 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 6a 32}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


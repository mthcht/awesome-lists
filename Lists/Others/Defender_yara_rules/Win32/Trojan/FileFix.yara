rule Trojan_Win32_FileFix_D_2147945794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.D!MTB"
        threat_id = "2147945794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = ".docx" wide //weight: 1
        $x_1_3 = {2d 00 63 00 20 00 70 00 69 00 6e 00 67 00 [0-80] 23 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


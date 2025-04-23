rule Trojan_Win32_SuspRootInstall_B_2147926861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRootInstall.B"
        threat_id = "2147926861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRootInstall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell -ex bypass" ascii //weight: 1
        $x_1_2 = "Import-Certificate" ascii //weight: 1
        $x_1_3 = {2d 00 46 00 69 00 6c 00 65 00 50 00 61 00 74 00 68 00 [0-32] 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 46 69 6c 65 50 61 74 68 [0-32] 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_SuspRootInstall_A_2147939803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRootInstall.A"
        threat_id = "2147939803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRootInstall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& certutil.exe" ascii //weight: 1
        $x_1_2 = "-addstore root" ascii //weight: 1
        $x_1_3 = "\\windows\\temp\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


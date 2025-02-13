rule PWS_Win32_Dofoil_A_2147647984_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dofoil.A"
        threat_id = "2147647984"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&module=grabbers" ascii //weight: 1
        $x_1_2 = {f8 50 6a 2f 68 ?? ?? ?? ?? 57 02 00 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Dofoil_C_2147650429_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dofoil.C"
        threat_id = "2147650429"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd=grab&data=" ascii //weight: 1
        $x_1_2 = "\\TurboFTP\\addrbk.dat" wide //weight: 1
        $x_1_3 = {8d 45 fc e8 ?? ?? ?? ?? 50 6a 00 6a 00 6a 28 6a 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 ?? 8d 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Dofoil_E_2147658182_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dofoil.E"
        threat_id = "2147658182"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/weblogs/recv.php" ascii //weight: 1
        $x_1_2 = "Hello cruel world" ascii //weight: 1
        $x_1_3 = "ie_injector_%d.txt" wide //weight: 1
        $x_1_4 = "elevated restart" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


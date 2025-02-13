rule Worm_Win32_Moriogu_A_2147596553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Moriogu.A"
        threat_id = "2147596553"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Moriogu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\Virus\\Romeo.vbp" wide //weight: 5
        $x_5_2 = "C:\\Boot.ini" wide //weight: 5
        $x_5_3 = "\\Policies\\System\\DisableRegistryTools" wide //weight: 5
        $x_5_4 = "\\Policies\\Microsoft\\Windows\\System\\DisableCMD" wide //weight: 5
        $x_5_5 = "\\Win2x.exe" wide //weight: 5
        $x_5_6 = "multi(0)disk(0)rdisk(0)partition(1)\\Romeo=\"Su PC esta infestada por un virus de ultima generacion\"" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


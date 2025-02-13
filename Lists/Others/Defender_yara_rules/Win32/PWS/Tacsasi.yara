rule PWS_Win32_Tacsasi_A_2147628874_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tacsasi.A"
        threat_id = "2147628874"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tacsasi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fb 12 fc 0d 6c 6c ff 80 0c 00 fc a0 6c 6c ff 6c 5c ff e0 1c}  //weight: 2, accuracy: High
        $x_1_2 = "?action=add&a=" wide //weight: 1
        $x_1_3 = "cmd.exe /c net stop SharedAccess" wide //weight: 1
        $x_1_4 = "drowssaP\\CUD\\skrewlatiV\\ERAWTFOS\\ENIHCAM_LACOL_YEKH" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


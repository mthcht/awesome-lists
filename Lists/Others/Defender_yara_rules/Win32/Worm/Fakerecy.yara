rule Worm_Win32_Fakerecy_A_2147611057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Fakerecy.A"
        threat_id = "2147611057"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakerecy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual Studio\\VB98\\" ascii //weight: 1
        $x_1_2 = "\\Recycled\\INFO2" wide //weight: 1
        $x_1_3 = "\\Recycled\\desktop.ini" wide //weight: 1
        $x_1_4 = "\\Recycled\\Recycled\\ctfmon.exe" wide //weight: 1
        $x_1_5 = "shellexecute=Recycled\\Recycled\\ctfmon.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


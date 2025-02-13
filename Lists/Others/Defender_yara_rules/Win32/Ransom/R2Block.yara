rule Ransom_Win32_R2Block_SU_2147768440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/R2Block.SU!MTB"
        threat_id = "2147768440"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "R2Block"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\obj\\Debug\\BMI DataSender.pdb" ascii //weight: 1
        $x_1_2 = "\\r2block_Wallpaper.jpg" ascii //weight: 1
        $x_1_3 = "envhost.exe" ascii //weight: 1
        $x_1_4 = ":\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_1_5 = "\\BMI DataSender.exe" ascii //weight: 1
        $x_1_6 = ":\\Users\\Reza\\Desktop\\001" ascii //weight: 1
        $x_1_7 = "!Re#za$2%Ba^ha*r" ascii //weight: 1
        $x_1_8 = "get_r2block_Wallpaper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


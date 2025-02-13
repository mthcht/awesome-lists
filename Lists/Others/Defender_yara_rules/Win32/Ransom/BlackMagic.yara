rule Ransom_Win32_BlackMagic_PA_2147836421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackMagic.PA!MTB"
        threat_id = "2147836421"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMagic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".BlackMagic" ascii //weight: 1
        $x_1_2 = "\\HackedByBlackMagic.txt" ascii //weight: 1
        $x_1_3 = "Black Magic Has Targeted You!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackMagic_A_2147836696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackMagic.A!dha"
        threat_id = "2147836696"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMagic"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "c:\\users\\public\\Documents\\MicrosoftUpdate.dll.BlackMagic" ascii //weight: 3
        $x_2_2 = "reg add \"hkey_current_user\\control panel\\desktop\" /v wallpaper /t reg_sz /d C:\\Users\\Public\\Documents\\back.bmp /f" ascii //weight: 2
        $x_2_3 = "del /F \"c:\\users\\public\\Documents\\back.bmp\"" ascii //weight: 2
        $x_2_4 = "reg add hkcu\\software\\microsoft\\windows\\currentversion\\policies\\system /v disabletaskmgr /t reg_dword /d 1 /f" ascii //weight: 2
        $x_2_5 = "\\HackedByBlackMagic.txt" ascii //weight: 2
        $x_2_6 = "ipconfig > c:\\users\\public\\Documents\\ip.txt" ascii //weight: 2
        $x_2_7 = "/BlackMagic2511" ascii //weight: 2
        $x_2_8 = {62 6c 61 6b 6d 61 67 69 63 (32 35|37 35)}  //weight: 2, accuracy: Low
        $x_1_9 = "193.182.144.85" ascii //weight: 1
        $x_1_10 = "5.230.70.49" ascii //weight: 1
        $x_1_11 = "/api/public/api/test?ip=&status=0&cnt=100&type=server&num=11111170" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}


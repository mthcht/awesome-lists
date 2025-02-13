rule Backdoor_Win32_DarkKomet_PA_2147759100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DarkKomet.PA!MTB"
        threat_id = "2147759100"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Go build ID: \"S8b0Bu4sIueomyIgwvW9/8tDFmeLjKNy2aRHATRZ5/fnHkdeFA7ysHAYaUmAz9/kY99_VXk9q6ANLJREYo2\"" ascii //weight: 5
        $x_1_2 = "Encrypt" ascii //weight: 1
        $x_1_3 = "at  fp= is  lr: of  on  pc= sp: sp=" ascii //weight: 1
        $x_1_4 = "m=+Inf, n -Inf.bat.cmd.com.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_DarkKomet_MA_2147809192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DarkKomet.MA!MTB"
        threat_id = "2147809192"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d 08 b8 4d 5a 00 00 66 39 03 74 ?? 33 c0 eb ?? 8b 43 3c 81 3c 18 50 45 00 00 75 ?? 8b 44 18 78 83 65 08 00 56 03 c3 8b 70 20 8b 48 18 57 8b 78 1c 03 f3 03 fb 89 4d fc 85 c9 74}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c1 8b c8 c1 e1 18 c1 f9 1f 81 e1 ?? ?? ?? ?? 8b f0 c1 e6 1f c1 fe 1f 81 e6 ?? ?? ?? ?? 33 ce 8b f0 c1 e6 1d c1 fe 1f 81 e6 ?? ?? ?? ?? 33 ce 8b f0 c1 e6 19 c1 fe 1f 81 e6 ?? ?? ?? ?? 33 ce 8b f0 c1 e6 1a c1 fe 1f 81 e6 ?? ?? ?? ?? 33 ce}  //weight: 1, accuracy: Low
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


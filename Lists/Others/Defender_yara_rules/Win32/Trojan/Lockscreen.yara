rule Trojan_Win32_Lockscreen_MA_2147841998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lockscreen.MA!MTB"
        threat_id = "2147841998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockscreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e9 04 0a d1 88 14 24 c7 06 01 00 00 00 8a 50 02 80 fa 3d 74 ?? ff 06 8a 0c bd 70 d4 51 00 c1 e1 04 33 db 8a da 8b 1c 9d 70 d4 51 00 c1 eb 02 0a cb 88 4c 24 01 8a 48 03 80 f9 3d 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lockscreen_AMMD_2147905528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lockscreen.AMMD!MTB"
        threat_id = "2147905528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockscreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WINLOCKBYAMPBYAMPBYAMPfsdjf" ascii //weight: 2
        $x_2_2 = "C:\\MBR.bin" ascii //weight: 2
        $x_2_3 = "DisableChangePassword" ascii //weight: 2
        $x_2_4 = "C:\\Users\\Public\\monkeiii.dll" ascii //weight: 2
        $x_2_5 = "/c TASKKILL /F /FI \"Imagename ne" ascii //weight: 2
        $x_2_6 = "AntiWinLockerTray.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


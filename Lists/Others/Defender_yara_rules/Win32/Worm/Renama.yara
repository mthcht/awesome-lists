rule Worm_Win32_Renama_A_2147600670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Renama.A"
        threat_id = "2147600670"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Renama"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 01 00 00 80 c7 44 24 ?? 64 00 00 00 c7 44 24 ?? 00 00 00 00 ff d7 8b 4c 24 ?? 8d 54 24 ?? 8d 44 24 ?? 52 50 6a 00 6a 00 68 38 95 40 00 51 ff 15 ?? ?? ?? ?? 8d 54 24 ?? 68 ?? ?? ?? ?? 52}  //weight: 10, accuracy: Low
        $x_1_2 = "%s\\Registry1.dll" ascii //weight: 1
        $x_1_3 = "%s\\ERSvc.exe" ascii //weight: 1
        $x_1_4 = "%s\\mmsg\\mmsg.exe" ascii //weight: 1
        $x_1_5 = "%s\\mmsg\\mcAfee.Update.exe" ascii //weight: 1
        $x_1_6 = "%s\\Config\\system.update.exe" ascii //weight: 1
        $x_1_7 = "%s\\Config\\Easy.Windows.Monitoring.exe" ascii //weight: 1
        $x_1_8 = "%s\\mails.dll" ascii //weight: 1
        $x_1_9 = "%s\\muhammad_is_my_prophet.txt" ascii //weight: 1
        $x_1_10 = "%s, your name is listed in terrorism organisation..!!!" ascii //weight: 1
        $x_1_11 = "%s, Namamu termasuk dalam daftar terrorist..!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}


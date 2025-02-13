rule Backdoor_Win32_Hecscen_A_2147628243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hecscen.A"
        threat_id = "2147628243"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hecscen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GetSniffer" ascii //weight: 1
        $x_1_2 = "GetMailer" ascii //weight: 1
        $x_1_3 = "IPCScan Complete!" ascii //weight: 1
        $x_1_4 = "RemoteCmd is Error!" ascii //weight: 1
        $x_1_5 = "GET http://%s:%s/msupdate.exe" ascii //weight: 1
        $x_1_6 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_4_7 = {6a 06 6a 01 6a 02 ff 15 ?? ?? ?? 10 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff ff 75 05 e9 ?? 00 00 00 6a 04 8d 8d ?? ?? ff ff 51 68 06 10 00 00 68 ff ff 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


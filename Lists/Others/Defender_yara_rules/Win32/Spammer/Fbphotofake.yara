rule Spammer_Win32_Fbphotofake_A_2147639793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Fbphotofake.A"
        threat_id = "2147639793"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Fbphotofake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "email=%s&pass=%s&login=Log%20In" ascii //weight: 1
        $x_1_2 = ".\\pipe\\facebook" ascii //weight: 1
        $x_1_3 = "[FACEBOOK] Network initialized successfully!!!" ascii //weight: 1
        $x_1_4 = "[FACEBOOK] Trying to login with %s" ascii //weight: 1
        $x_1_5 = "[FACEBOOK] Spam thread started." ascii //weight: 1
        $x_1_6 = "[FACEBOOK] Written, starting spam..." ascii //weight: 1
        $x_1_7 = "[FACEBOOK] Start sending %d POST data!" ascii //weight: 1
        $x_1_8 = "%s?act=fb_stat&num=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


rule PWS_Win32_XSpy_A_2147626982_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/XSpy.A"
        threat_id = "2147626982"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "XSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "78"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%2\\Insertable" ascii //weight: 10
        $x_10_2 = "CLSID\\%1\\AuxUserType\\" ascii //weight: 10
        $x_10_3 = "X-Mailer: " ascii //weight: 10
        $x_10_4 = "RCPT TO: " ascii //weight: 10
        $x_10_5 = "Send mail end error" ascii //weight: 10
        $x_10_6 = "Password error" ascii //weight: 10
        $x_10_7 = "unHook" ascii //weight: 10
        $x_1_8 = "c:\\xlwj" ascii //weight: 1
        $x_1_9 = "ALT + CTL + K" ascii //weight: 1
        $x_1_10 = "xlspy_soft@tom.com" ascii //weight: 1
        $x_1_11 = "\\mscon.wav" ascii //weight: 1
        $x_1_12 = "%s\\prd.ini" ascii //weight: 1
        $x_1_13 = "smtp.tom.com" ascii //weight: 1
        $x_1_14 = "gb2312" ascii //weight: 1
        $x_1_15 = "friend1" ascii //weight: 1
        $x_1_16 = "lc_spydog@tom.com" ascii //weight: 1
        $x_1_17 = "%s\\sprc.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}


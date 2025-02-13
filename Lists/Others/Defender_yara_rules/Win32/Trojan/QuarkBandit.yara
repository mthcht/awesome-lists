rule Trojan_Win32_QuarkBandit_A_2147733754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QuarkBandit.A!dha"
        threat_id = "2147733754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QuarkBandit"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 06 80 c1 ?? 80 f1 ?? 88 0c 06 46 3b f2 7c ef}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 b8 49 6f 63 70 66 c7 45 bc 53 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QuarkBandit_A_2147733754_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QuarkBandit.A!dha"
        threat_id = "2147733754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QuarkBandit"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 0c 06 80 c1 ?? 80 f1 ?? 88 0c 06 46 3b f2}  //weight: 3, accuracy: Low
        $x_1_2 = "POST HTTP://%s:%d/ HTTP/1.1" ascii //weight: 1
        $x_1_3 = "RtlGetVersion is Fail." ascii //weight: 1
        $x_1_4 = "ChangeServiceConfig2 info failed." ascii //weight: 1
        $x_1_5 = "UnregisterClass is error(%d)" ascii //weight: 1
        $x_1_6 = "worker receive the exiting Message..." ascii //weight: 1
        $x_2_7 = "A~123A" ascii //weight: 2
        $x_2_8 = "B!@#$B" ascii //weight: 2
        $x_2_9 = "C%^&*C" ascii //weight: 2
        $x_2_10 = "D()_+D" ascii //weight: 2
        $x_2_11 = "A!123A" ascii //weight: 2
        $x_2_12 = "B\"234B" ascii //weight: 2
        $x_2_13 = "C#345C" ascii //weight: 2
        $x_2_14 = "D$456D" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}


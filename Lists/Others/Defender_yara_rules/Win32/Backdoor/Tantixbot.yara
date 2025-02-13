rule Backdoor_Win32_Tantixbot_2147582344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tantixbot"
        threat_id = "2147582344"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tantixbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\botnet\\old\\AntiX\\AntiX\\AntiX.vbp" wide //weight: 5
        $x_3_2 = "a.n.t.i.x.b.o.t" wide //weight: 3
        $x_1_3 = ".shutdown" wide //weight: 1
        $x_1_4 = ".restart" wide //weight: 1
        $x_1_5 = ".hostname" wide //weight: 1
        $x_1_6 = ".localip" wide //weight: 1
        $x_1_7 = ".stopmsnspread" wide //weight: 1
        $x_1_8 = ".stopspreadmsn" wide //weight: 1
        $x_1_9 = ".spreadmsn" wide //weight: 1
        $x_1_10 = ".msnspread" wide //weight: 1
        $x_1_11 = ".findhost" wide //weight: 1
        $x_1_12 = ".sfversion" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


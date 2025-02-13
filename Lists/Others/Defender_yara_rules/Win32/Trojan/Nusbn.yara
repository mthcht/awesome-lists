rule Trojan_Win32_Nusbn_B_2147696281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nusbn.B"
        threat_id = "2147696281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nusbn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?action=getExeList&pcid=" ascii //weight: 1
        $x_1_2 = "shell am start -n" ascii //weight: 1
        $x_1_3 = "kill-server" ascii //weight: 1
        $x_1_4 = "?action=getDriver" ascii //weight: 1
        $x_1_5 = "VID_%04x&PID_%04x" wide //weight: 1
        $x_5_6 = "222.186.60.89:1123" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


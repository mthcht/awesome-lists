rule Trojan_Win32_Srendiv_A_2147626117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Srendiv.A"
        threat_id = "2147626117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Srendiv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/client_register_av.do?%s%d&ver=%.2f&aver=%.2f&%s=%s" ascii //weight: 1
        $x_1_2 = {6d 6e 6d 73 72 76 63 00 2d 70 00 00 6d 73 72 76 63}  //weight: 1, accuracy: High
        $x_1_3 = "%s\\drivers\\%s%s" ascii //weight: 1
        $x_1_4 = "\\%08x.exe" ascii //weight: 1
        $x_1_5 = "Windows File Protection" ascii //weight: 1
        $x_1_6 = "ZwCreateProcess" ascii //weight: 1
        $x_1_7 = "%s -self" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Srendiv_A_2147626117_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Srendiv.A"
        threat_id = "2147626117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Srendiv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/client_register_av.do?%s%d&ver=%.2f&aver=%.2f&%s=%s" ascii //weight: 10
        $x_10_2 = "\\%08x.exe" ascii //weight: 10
        $x_10_3 = "Windows File Protection" ascii //weight: 10
        $x_1_4 = "_LiveUpdate" ascii //weight: 1
        $x_1_5 = "0D2A401E-3E9F-4e25-B035-4B01FDEBD85D" ascii //weight: 1
        $x_1_6 = "GoogleUpdaterService.exe" ascii //weight: 1
        $x_1_7 = "OSE.EXE" ascii //weight: 1
        $x_1_8 = "&u_name=" ascii //weight: 1
        $x_1_9 = "stormliv.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Rotker_A_2147623528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rotker.A"
        threat_id = "2147623528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rotker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00 76 00 65 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 33 00 36 00 30 00 73 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 3, accuracy: High
        $x_2_2 = "\\SystemRoot\\System32\\ntdll.d11" wide //weight: 2
        $x_1_3 = "POST /cc.aspx HTTP/1.0" ascii //weight: 1
        $x_1_4 = "Accept: text/html, money/rmb" ascii //weight: 1
        $x_1_5 = "eset.|" ascii //weight: 1
        $x_1_6 = "TTraveler.exe" wide //weight: 1
        $x_1_7 = "WINNT_SFC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


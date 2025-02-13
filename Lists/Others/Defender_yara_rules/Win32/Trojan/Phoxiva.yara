rule Trojan_Win32_Phoxiva_A_2147691706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phoxiva.A"
        threat_id = "2147691706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phoxiva"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YXBpLnZrLmNvbS9tZXRob2Qvd2FsbC5nZXQ/Y291bnQ9MSZvd25lcl9pZD0tODE5NzIzODY=" ascii //weight: 1
        $x_1_2 = "f0xy" wide //weight: 1
        $x_1_3 = "<knock>" ascii //weight: 1
        $x_1_4 = "<port>" ascii //weight: 1
        $x_1_5 = "Bot_ID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


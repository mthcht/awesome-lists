rule Trojan_Win32_Vaklik_C_2147612342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vaklik.C"
        threat_id = "2147612342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vaklik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 4c ff 0a 00 4e 38 ff 04 38 ff 04 28 ff 0a 0b 00 08 00 04 28 ff 3a 18 ff 0c 00 fb ef f8 fe 60 23 6c ff f4 01 f4 ff}  //weight: 1, accuracy: High
        $x_1_2 = "EVENT_SINK_AddRef" ascii //weight: 1
        $x_1_3 = "EVENT_SINK_Release" ascii //weight: 1
        $x_1_4 = "EVENT_SINK_QueryInterface" ascii //weight: 1
        $x_1_5 = "stub.vbp" wide //weight: 1
        $x_1_6 = "tmp.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


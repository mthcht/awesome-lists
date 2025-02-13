rule TrojanSpy_MSIL_Fitin_A_2147685471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Fitin.A"
        threat_id = "2147685471"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fitin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c210cC5nbWFpbC5jb20=" ascii //weight: 1
        $x_1_2 = "XEZpbGVkTmFtZS5leGU=" ascii //weight: 1
        $x_1_3 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" ascii //weight: 1
        $x_1_4 = "XTogUHJvZ3JhbSBJcyBPZmYgTm93" ascii //weight: 1
        $x_1_5 = "XTogTmV3IEluZmVjdGlvbg==" ascii //weight: 1
        $x_1_6 = "TmV3IEluZmVjdGlvbiEhIQ==" ascii //weight: 1
        $x_1_7 = "W0JhY2tzcGFjZV0=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


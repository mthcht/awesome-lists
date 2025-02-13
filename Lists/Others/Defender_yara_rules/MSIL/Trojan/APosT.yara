rule Trojan_MSIL_APosT_MA_2147811264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/APosT.MA!MTB"
        threat_id = "2147811264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "APosT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ajwfdaidwa" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "kjgsdogfewof" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


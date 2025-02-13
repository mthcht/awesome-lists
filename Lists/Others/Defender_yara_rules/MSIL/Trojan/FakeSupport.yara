rule Trojan_MSIL_FakeSupport_MA_2147813146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FakeSupport.MA!MTB"
        threat_id = "2147813146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeSupport"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "Svhostserver" wide //weight: 1
        $x_1_3 = "gncmdstore.com/api_withoutmac" wide //weight: 1
        $x_1_4 = "GetsupremoId" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Wow6432Node\\Supremo" wide //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_IIStealer_DA_2147920321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IIStealer.DA!MTB"
        threat_id = "2147920321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IIStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "if(navigator.userAgent.toLocaleLowerCase().indexOf(\"baidu\") == -1){document.title" ascii //weight: 1
        $x_1_2 = ".replace(new RegExp(" ascii //weight: 1
        $x_1_3 = "String.fromCharCode(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


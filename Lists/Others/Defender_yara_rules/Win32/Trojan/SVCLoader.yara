rule Trojan_Win32_SVCLoader_AM_2147820357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SVCLoader.AM!MTB"
        threat_id = "2147820357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SVCLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ellipse" ascii //weight: 1
        $x_1_2 = "GetProcAddress" ascii //weight: 1
        $x_1_3 = "LoadLibraryA" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "FillRect" ascii //weight: 1
        $x_1_6 = "sxv.dll" ascii //weight: 1
        $x_1_7 = "LoadLibraryC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SVCLoader_EM_2147827804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SVCLoader.EM!MTB"
        threat_id = "2147827804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SVCLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yeFjFSifq68y5DVxvhk5tZGI4zQZf8z5e" ascii //weight: 1
        $x_1_2 = "AT5DxVldu" ascii //weight: 1
        $x_1_3 = "DWrGmSO" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


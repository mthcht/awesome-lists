rule Ransom_Win32_Purga_DA_2147773312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Purga.DA!MTB"
        threat_id = "2147773312"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Purga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_2 = "Sandbox detected, work interrupted!" ascii //weight: 1
        $x_1_3 = "recoveryenabled No" ascii //weight: 1
        $x_1_4 = "bootstatuspolicy ignoreallfailures" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


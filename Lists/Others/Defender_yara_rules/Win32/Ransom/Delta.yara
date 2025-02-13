rule Ransom_Win32_Delta_MK_2147786271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Delta.MK!MTB"
        threat_id = "2147786271"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Delta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Info.hta" ascii //weight: 1
        $x_1_2 = ".[Delta]" ascii //weight: 1
        $x_1_3 = "Delta Encrypt" ascii //weight: 1
        $x_1_4 = "vssadmin.exe delete shadows /all" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\delog.cmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


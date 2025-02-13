rule Ransom_Win32_Blackout_PA_2147752356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Blackout.PA!MTB"
        threat_id = "2147752356"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackout"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL2FsbCAvcXVpZXQgJiBiY2RlZGl0LmV4ZSAvc2V0IHtkZWZhdWx0fSByZWNvdmVyeWVuYWJsZWQgbm8gJiBiY2RlZGl0LmV4ZSAvc2V0IHtkZWZhdWx0fSBib290c3RhdHVzcG9saWN5IGlnbm9yZWFsbGZhaWx1cmVz" ascii //weight: 1
        $x_1_2 = "RGlzYWJsZVRhc2tNZ3I=" ascii //weight: 1
        $x_1_3 = "LnNxbGl0ZTM=" ascii //weight: 1
        $x_1_4 = "LmFjY2Ry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Blackout_PB_2147752360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Blackout.PB!MTB"
        threat_id = "2147752360"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackout"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet & bcdedit.exe /set {default} recoveryenabled no" wide //weight: 1
        $x_1_2 = "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" wide //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = ".sqlitedb" wide //weight: 1
        $x_1_5 = ".accde" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


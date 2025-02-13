rule Ransom_Win32_WannaCry_PA_2147783716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCry.PA!MTB"
        threat_id = "2147783716"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".wannacry" ascii //weight: 1
        $x_1_2 = "LocalBitcoins" ascii //weight: 1
        $x_1_3 = "@Please_Read_Me@.txt" ascii //weight: 1
        $x_1_4 = "WannaCry 3.0  @Please_Read_Me@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCry_ARA_2147919876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCry.ARA!MTB"
        threat_id = "2147919876"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".wcry" ascii //weight: 2
        $x_2_2 = "reg add HKCU\\Software" ascii //weight: 2
        $x_2_3 = "DisableCMD" ascii //weight: 2
        $x_2_4 = "DisableTaskMgr" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


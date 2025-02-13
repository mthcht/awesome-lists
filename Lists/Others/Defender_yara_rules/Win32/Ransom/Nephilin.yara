rule Ransom_Win32_Nephilin_A_2147755522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nephilin.A!MTB"
        threat_id = "2147755522"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nephilin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NEPHILIN-DECRYPT.txt" ascii //weight: 1
        $x_1_2 = "/c bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_3 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_4 = "wbadmin delete catalog -quiet" ascii //weight: 1
        $x_1_5 = "wmic shadowcopy delete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


rule Ransom_MSIL_Hydracrypt_AHY_2147850643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hydracrypt.AHY!MTB"
        threat_id = "2147850643"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hydracrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 11 06 11 05 6f ?? ?? ?? 0a 7d 27 00 00 04 08 11 06 fe 06 32 00 00 06 73 27 00 00 0a 28 ?? ?? ?? 2b 2d 09 09 11 04 9a 28 ?? ?? ?? 06 11 04 17 58 13 04 11 04 09 8e 69 32 b5}  //weight: 2, accuracy: Low
        $x_1_2 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete" wide //weight: 1
        $x_1_3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" wide //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


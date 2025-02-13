rule Ransom_MSIL_KobosCrypt_SN_2147771746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/KobosCrypt.SN!MTB"
        threat_id = "2147771746"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KobosCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ObfuscatedByGoliath" ascii //weight: 1
        $x_1_2 = "get_TotalFreeSpace" ascii //weight: 1
        $x_1_3 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_4 = "set_UseShellExecute" ascii //weight: 1
        $x_1_5 = "WriteAllText" ascii //weight: 1
        $x_1_6 = "GetDrives" ascii //weight: 1
        $x_1_7 = "get_IsAttached" ascii //weight: 1
        $x_10_8 = "svchost.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


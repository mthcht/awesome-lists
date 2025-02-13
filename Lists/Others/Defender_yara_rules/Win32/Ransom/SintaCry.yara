rule Ransom_Win32_SintaCry_A_2147721477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SintaCry.A"
        threat_id = "2147721477"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SintaCry"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "SintaRun.py" ascii //weight: 15
        $x_15_2 = "destroy_shadow_copy" ascii //weight: 15
        $x_15_3 = "Crypto.CipherR(" ascii //weight: 15
        $x_5_4 = "api.php?info=s" ascii //weight: 5
        $x_5_5 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 5
        $x_5_6 = "/t REG_DWORD /v DisableRegistryTools /d 1" ascii //weight: 5
        $x_1_7 = "*.unity3d" ascii //weight: 1
        $x_1_8 = "*.vmdk" ascii //weight: 1
        $x_1_9 = "*.vmx" ascii //weight: 1
        $x_1_10 = "*.SQLITEDB" ascii //weight: 1
        $x_1_11 = "*.SQLITE3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_15_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_15_*) and 5 of ($x_1_*))) or
            ((3 of ($x_15_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}


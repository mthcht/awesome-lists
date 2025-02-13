rule Ransom_Win32_DCrSrv_AK_2147913833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DCrSrv.AK"
        threat_id = "2147913833"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DCrSrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "DCrSrv\\Release\\DCrSrv.pdb" ascii //weight: 5
        $x_1_2 = "DCmod\\DiskCryptor\\DCrypt\\Bin\\boot\\boot_hook_small.pdb" ascii //weight: 1
        $x_1_3 = "DCmod\\DiskCryptor\\DCrypt\\Bin\\boot\\boot_load.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


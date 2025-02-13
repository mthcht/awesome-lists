rule Backdoor_Win32_Rithreto_A_2147656246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rithreto.A"
        threat_id = "2147656246"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rithreto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bitcoin botnet" ascii //weight: 1
        $x_1_2 = "Bitcoin Miner Builder" ascii //weight: 1
        $x_1_3 = "upx.exe -9 miner.exe" ascii //weight: 1
        $x_1_4 = "worker_pass" ascii //weight: 1
        $x_1_5 = "worker_name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


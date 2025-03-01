rule Ransom_Win32_lockbit_DB_2147771353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/lockbit.DB!MTB"
        threat_id = "2147771353"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tor Browser may be blocked in your country or corporate network" ascii //weight: 1
        $x_1_2 = "Restore-My-Files.txt" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "gethostbyaddr" ascii //weight: 1
        $x_1_5 = "BCryptGenRandom" ascii //weight: 1
        $x_1_6 = "creased price" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


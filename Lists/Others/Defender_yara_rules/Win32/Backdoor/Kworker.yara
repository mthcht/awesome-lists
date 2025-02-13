rule Backdoor_Win32_Kworker_S_2147745199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kworker.S!MSR"
        threat_id = "2147745199"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kworker"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://193.29.15.147" ascii //weight: 1
        $x_1_2 = "kworker/u8:7-ev" ascii //weight: 1
        $x_1_3 = "MsMpEng.exe" ascii //weight: 1
        $x_1_4 = "/usr/local/bin/update-notifier" ascii //weight: 1
        $x_1_5 = "Access-Control: aW5mbw==" ascii //weight: 1
        $x_1_6 = "Nzg6QUM6QzA6M0Q6Q0U6MzkKV2luZG93cwppMzg2CjAu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


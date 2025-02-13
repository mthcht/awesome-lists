rule Trojan_Win64_Dirthy_YAB_2147922429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dirthy.YAB!MTB"
        threat_id = "2147922429"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dirthy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe-CommandClear-RecycleBin -Force -ErrorAction SilentlyContinue" ascii //weight: 10
        $x_1_2 = "Unregister-ScheduledTask -TaskName $task.TaskName -Confirm" ascii //weight: 1
        $x_1_3 = "__imp_CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "code/rustc/3f5fd8dd41153bc5fdca9427e9e05be2c767ba23\\library\\std\\src\\io\\error\\repr_bitpacked.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_WinNT_Mansys_2147627423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Mansys"
        threat_id = "2147627423"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Mansys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 68 80 00 00 00 6a 02 56 6a 02 68 00 00 00 40 ff 75 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 e3 00 f0 66 81 fb 00 30 75 1e [0-21] 75 ?? 66 [0-6] c7 05 74 15}  //weight: 1, accuracy: Low
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_4 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_5 = "\\\\.\\https" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


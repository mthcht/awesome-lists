rule HackTool_Win64_WatchDogKiller_A_2147956261_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/WatchDogKiller.A"
        threat_id = "2147956261"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "WatchDogKiller"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\.\\amsdk" wide //weight: 1
        $x_1_2 = "\\\\.\\B5A6B7C9-1E31-4E62-91CB-6078ED1E" wide //weight: 1
        $x_1_3 = "EDR Terminator Tool" ascii //weight: 1
        $x_1_4 = "Attempting to terminate PID %lu..." ascii //weight: 1
        $x_1_5 = "Attempting to register process %d" ascii //weight: 1
        $x_1_6 = "WatchDogKiller.pdb" ascii //weight: 1
        $x_1_7 = {ba 48 20 00 80 48 8b ce ff 15}  //weight: 1, accuracy: High
        $x_1_8 = {ba 10 20 00 80 [0-16] 48 8b ce ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


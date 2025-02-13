rule Backdoor_Win32_Bandook_BM_2147769610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bandook.BM!MSR"
        threat_id = "2147769610"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandook"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KbdLayerDescriptor" ascii //weight: 1
        $x_1_2 = "GetKeyState" ascii //weight: 1
        $x_1_3 = "X:\\D BACKUP 29032014" ascii //weight: 1
        $x_1_4 = "Cipher not initialized" ascii //weight: 1
        $x_1_5 = "DCPblockciphers" ascii //weight: 1
        $x_1_6 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


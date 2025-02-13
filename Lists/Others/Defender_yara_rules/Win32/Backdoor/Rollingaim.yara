rule Backdoor_Win32_Rollingaim_A_2147898119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rollingaim.A!dha"
        threat_id = "2147898119"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rollingaim"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OwaModule" ascii //weight: 1
        $x_1_2 = "get_ServerVariables" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "get_Cookies" ascii //weight: 1
        $x_1_5 = "GetFiles" ascii //weight: 1
        $x_1_6 = "set_UseShellExecute" ascii //weight: 1
        $x_1_7 = "BinaryWrite" ascii //weight: 1
        $x_1_8 = "Microsoft.Exchange.Clients.Event.pdb" ascii //weight: 1
        $x_1_9 = "Microsoft.Exchange.Clients.Event.dll" wide //weight: 1
        $x_1_10 = {52 66 68 6e 20 4d 18 22 76 b5 33 11 12 33 0c 6d 0a 20 4d 18 22 9e a1 29 61 1c 76 b5 05 19 01 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}


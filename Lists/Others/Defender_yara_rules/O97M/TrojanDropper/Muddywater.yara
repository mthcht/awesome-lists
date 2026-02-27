rule TrojanDropper_O97M_Muddywater_SI_2147963702_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Muddywater.SI!MTB"
        threat_id = "2147963702"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Muddywater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "giv = giv & Chr((Val(Mid(inp, con, 3))))" ascii //weight: 1
        $x_1_2 = "epath = Left(path, Len(path) - 4) & \".exe" ascii //weight: 1
        $x_1_3 = "objShell.ShellExecute epath, \"\", \"\", \"open\", 1" ascii //weight: 1
        $x_1_4 = "path = \"C:\\\\Users\\\\Public\\\\Documents\\\\MicrosoftWordUser.log" ascii //weight: 1
        $x_1_5 = "app = give(UserForm1.TextBox1.Text)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Muddywater_SJ_2147963703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Muddywater.SJ!MTB"
        threat_id = "2147963703"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Muddywater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MsgBox \"Failed to start process. Error: \" & Err.LastDllError" ascii //weight: 1
        $x_1_2 = "hstring = Replace(hstring, \":\", \"\")" ascii //weight: 1
        $x_1_3 = "result(i) = Val(\"&H\" & Mid(hstring, i * 2 + 1, 2))" ascii //weight: 1
        $x_1_4 = "pathfile = userProfile & \"\\Downloads\\pic.LOG" ascii //weight: 1
        $x_1_5 = {62 79 74 65 73 61 70 70 20 3d 20 44 65 63 68 65 78 28 55 73 65 72 46 6f 72 6d 31 2e [0-7] 2e 54 65 78 74 29}  //weight: 1, accuracy: Low
        $x_1_6 = "ret = CreateADirect(path, vbNullString, 0, 0, 0, CREATE_NO_WINDOW, 0, vbNullString, tsi, tpi)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


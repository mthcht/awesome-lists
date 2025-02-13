rule Virus_Win32_Stuly_A_2147598779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Stuly.A"
        threat_id = "2147598779"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Stuly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set iwwMdGn=CreateObject(\"Outlook.Application\")" ascii //weight: 1
        $x_1_2 = "For DTJFnSW=1 To 1590" ascii //weight: 1
        $x_1_3 = "Set SpNaAmn=iwwMdGn.CreateItem(0)" ascii //weight: 1
        $x_1_4 = "SpNaAmn.Body = \"Check this out and tell me what you think! I think it's great!\" & vbcrlf & \"\"SpNaAmn.DeleteAfterSubmit = True" ascii //weight: 1
        $x_1_5 = "SpNaAmn.Attachments.Add(\"C:\\slutty19.avi.exe\")" ascii //weight: 1
        $x_1_6 = "SpNaAmn.Subject = \"This is a must see!\"" ascii //weight: 1
        $x_1_7 = "SpNaAmn.To = iwwMdGn.GetNameSpace(\"MAPI\").AddressLists(1).AddressEntries(X)" ascii //weight: 1
        $x_1_8 = "SpNaAmn.Send" ascii //weight: 1
        $x_1_9 = "iwwMdGn.Quit" ascii //weight: 1
        $x_1_10 = "C:\\nxOuEKvNO.vbs" ascii //weight: 1
        $x_10_11 = {e8 f2 01 00 00 40 74 18 e8 f7 07 00 00 83 bd 6f 39 45 00 00 76 0a e8 02 02 00 00 83 f8 00 75 e8 33 f6 03 b5 b7 3c 45 00 56 ff 95 f3 37 45 00 c3 e8 3a 03 00 00 ff a0 d2 37 45 00 e8 3c 03 00 00 ff a0 c6 37 45 00 e8 31 03 00 00 ff a0 ae 37 45 00 e8 26 03 00 00 ff a0 ba 37 45 00 e8 1b 03 00 00 ff a0 a2 37 45 00 60 66 c7 85 6e 3c 45 00 00 00 bb 09 1b ff ff 81 c3 f7 e4 00 00 03 9d 3f 3b 45 00 bf 00 00 00 00 03 7b 78 03 bd 70 3c 45 00 47 83 c7 1b 8b 1f 83 c7 04 03 9d 70 3c 45 00 89 9d 53 3b 45 00 8b 1f 03 9d 70 3c 45 00 83 c7 04 89 9d 17 38 45 00 8b 1f 03 9d 70 3c 45 00 89 9d 4b 3b 45 00 ba ff ff ff ff 23 95 17 38 45 00 c7 85 47 3b 45 00 00 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


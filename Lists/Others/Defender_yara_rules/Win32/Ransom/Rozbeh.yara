rule Ransom_Win32_Rozbeh_AN_2147821833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rozbeh.AN!MTB"
        threat_id = "2147821833"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozbeh"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "for /f %%%%F in ('dir *.exe /s /b') do copy /y Rozbeh.exe" ascii //weight: 1
        $x_1_2 = "Rozbeh.bat" ascii //weight: 1
        $x_1_3 = "DeskFL.vbs" ascii //weight: 1
        $x_1_4 = "cmd.exe /c copy /y ..\\Rozbeh.exe %%AppData%%\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_1_5 = "Scanner.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

